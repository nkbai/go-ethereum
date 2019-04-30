// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package trie

import (
	"fmt"
	"io"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
)

var indices = []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f", "[17]"}

type node interface {
	fstring(string) string
	cache() (hashNode, bool)
	canUnload(cachegen, cachelimit uint16) bool
}
//参考这里: https://github.com/nkbai/go-ethereum-code-analysis/blob/master/picture/trie_4.png
/*
这三种类型覆盖了一个普通Trie(也许是PatriciaTrie)的所有节点需求。任何一个[k,v]类型数据被插入一个MPT时，
会以k字符串为路径沿着root向下延伸，在此次插入结束时首先成为一个valueNode，
k会以自顶点root起到到该节点止的key path形式存在。但之后随着其他节点的不断插入和删除，根据MPT结构的要求，
原有节点可能会变化成其他node实现类型，同时MPT中也会不断裂变或者合并出新的(父)节点。比如：

	假设一个shortNode S已经有一个子节点A，现在要新插入一个子节点B，那么会有两种可能，
要么新节点B沿着A的路径继续向下，这样S的子节点会被更新；要么S的Key分裂成两段，前一段分配给S作为新的Key，
同时裂变出一个新的fullNode作为S的子节点，以同时容纳B，以及需要更新的A。

	如果一个fullNode原本只有两个子节点，现在要删除其中一个子节点，那么这个fullNode就会退化为shortNode，
同时保留的子节点如果是shortNode，还可以跟它再合并。
	如果一个shortNode的子节点是叶子节点同时又被删除了，那么这个shortNode就会退化成一个valueNode，成为一个叶子节点。

诸如此类的情形还有很多，提前设想过这些案例，才能正确实现MPT的插入/删除/查找等操作。当然，所有查找树(search tree)结构的操作，免不了用到递归。
*/
type (
	/*
		 是一个可以携带多个子节点的父(枝)节点。它有一个容量为17的node数组成员变量Children，
		数组中前16个空位分别对应16进制(hex)下的0-9a-f，这样对于每个子节点，根据其key值16进制形式下的第一位的值，
		就可挂载到Children数组的某个位置，fullNode本身不再需要额外key变量；Children数组的第17位，留给该fullNode的数据部分。
		fullNode明显继承了原生trie的特点，而每个父节点最多拥有16个分支也包含了基于总体效率的考量。
	*/
	fullNode struct {
		Children [17]node // Actual trie node data to encode/decode (needs custom encoder)
		flags    nodeFlag
	}
	//对应的是分支节点
	/*
		 是一个仅有一个子节点的父(枝)节点。它的成员变量Val指向一个子节点，
		而成员Key是一个任意长度的字符串(字节数组[]byte)。显然shortNode的设计体现了PatriciaTrie的特点，
		通过合并只有一个子节点的父节点和其子节点来缩短trie的深度，结果就是有些节点会有长度更长的key。
	*/
	shortNode struct {
		Key   []byte
		Val   node //valueNode此时是叶节点,或者fullNode,此时是branch node
		flags nodeFlag
	}
	//扩展节点和叶子节点
	/*
		特殊的那个 - hashNode
		hashNode 跟valueNode一样，也是字符数组[]byte的一个别名，同样存放32byte的哈希值，也没有子节点。
		不同的是，hashNode是fullNode或者shortNode对象的RLP哈希值，所以它跟valueNode在使用上有着莫大的不同。

		在MPT中，hashNode几乎不会单独存在(有时遍历遇到一个hashNode往往因为原本的node被折叠了)，
		而是以nodeFlag结构体的成员(nodeFlag.hash)的形式，被fullNode和shortNode间接持有。
		一旦fullNode或shortNode的成员变量(包括子结构)发生任何变化，它们的hashNode就一定需要更新。
		所以在trie.Trie结构体的insert()，delete()等函数实现中，可以看到除了新创建的fullNode、shortNode，
		那些子结构有所改变的fullNode、shortNode的nodeFlag成员也会被重设，hashNode会被清空。在下次trie.Hash()调用时，
		整个MPT自底向上的遍历过程中，所有清空的hashNode会被重新赋值。这样trie.Hash()结束后，我们可以得到一个根节点root的hashNode，
		它就是此时此刻这个MPT结构的哈希值。上文中提到的，Block的成员变量Root、TxHash、ReceiptHash的生成，正是源出于此。

		明显的，hashNode体现了MerkleTree的特点：每个父节点的哈希值来源于所有子节点哈希值的组合，
		一个顶点的哈希值能够代表一整个树形结构。valueNode加上之前的fullNode，shortNode，valueNode，
		构成了一个完整的Merkle-PatriciaTrie结构，很好的融合了各种原型结构的优点，又根据Ethereum系统的实际情况，
		作了实际的优化和平衡。MPT这个数据结构在设计中的种种细节，的确值得好好品味。
	*/
	hashNode  []byte
	/*
		充当MPT的叶子节点。它其实是字节数组[]byte的一个别名，不带子节点。
		在使用中，valueNode就是所携带数据部分的RLP哈希值，长度32byte，
		数据的RLP编码值作为valueNode的匹配项存储在数据库里。
	*/
	valueNode []byte
)

// nilValueNode is used when collapsing internal trie nodes for hashing, since
// unset children need to serialize correctly.
var nilValueNode = valueNode(nil)

// EncodeRLP encodes a full node into the consensus RLP format.
func (n *fullNode) EncodeRLP(w io.Writer) error {
	var nodes [17]node

	for i, child := range &n.Children {
		if child != nil {
			nodes[i] = child
		} else {
			nodes[i] = nilValueNode
		}
	}
	return rlp.Encode(w, nodes)
}

func (n *fullNode) copy() *fullNode   { copy := *n; return &copy }
func (n *shortNode) copy() *shortNode { copy := *n; return &copy }

// nodeFlag contains caching-related metadata about a node.
type nodeFlag struct {
	hash  hashNode // cached hash of the node (may be nil)
	gen   uint16   // cache generation counter
	dirty bool     // whether the node has changes that must be written to the database
}

// canUnload tells whether a node can be unloaded.
func (n *nodeFlag) canUnload(cachegen, cachelimit uint16) bool {
	return !n.dirty && cachegen-n.gen >= cachelimit
}

func (n *fullNode) canUnload(gen, limit uint16) bool  { return n.flags.canUnload(gen, limit) }
func (n *shortNode) canUnload(gen, limit uint16) bool { return n.flags.canUnload(gen, limit) }
func (n hashNode) canUnload(uint16, uint16) bool      { return false }
func (n valueNode) canUnload(uint16, uint16) bool     { return false }

func (n *fullNode) cache() (hashNode, bool)  { return n.flags.hash, n.flags.dirty }
func (n *shortNode) cache() (hashNode, bool) { return n.flags.hash, n.flags.dirty }
func (n hashNode) cache() (hashNode, bool)   { return nil, true }
func (n valueNode) cache() (hashNode, bool)  { return nil, true }

// Pretty printing.
func (n *fullNode) String() string  { return n.fstring("") }
func (n *shortNode) String() string { return n.fstring("") }
func (n hashNode) String() string   { return n.fstring("") }
func (n valueNode) String() string  { return n.fstring("") }

func (n *fullNode) fstring(ind string) string {
	resp := fmt.Sprintf("[\n%s  ", ind)
	for i, node := range &n.Children {
		if node == nil {
			resp += fmt.Sprintf("%s: <nil> ", indices[i])
		} else {
			resp += fmt.Sprintf("%s: %v", indices[i], node.fstring(ind+"  "))
		}
	}
	return resp + fmt.Sprintf("\n%s] ", ind)
}
func (n *shortNode) fstring(ind string) string {
	return fmt.Sprintf("{%x: %v} ", n.Key, n.Val.fstring(ind+"  "))
}
func (n hashNode) fstring(ind string) string {
	return fmt.Sprintf("<%x> ", []byte(n))
}
func (n valueNode) fstring(ind string) string {
	return fmt.Sprintf("%x ", []byte(n))
}

func mustDecodeNode(hash, buf []byte, cachegen uint16) node {
	n, err := decodeNode(hash, buf, cachegen)
	if err != nil {
		panic(fmt.Sprintf("node %x: %v", hash, err))
	}
	return n
}

// decodeNode parses the RLP encoding of a trie node.
func decodeNode(hash, buf []byte, cachegen uint16) (node, error) {
	if len(buf) == 0 {
		return nil, io.ErrUnexpectedEOF
	}
	elems, _, err := rlp.SplitList(buf)
	if err != nil {
		return nil, fmt.Errorf("decode error: %v", err)
	}
	switch c, _ := rlp.CountValues(elems); c {
	case 2:
		n, err := decodeShort(hash, elems, cachegen)
		return n, wrapError(err, "short")
	case 17:
		n, err := decodeFull(hash, elems, cachegen)
		return n, wrapError(err, "full")
	default:
		return nil, fmt.Errorf("invalid number of list elements: %v", c)
	}
}

func decodeShort(hash, elems []byte, cachegen uint16) (node, error) {
	kbuf, rest, err := rlp.SplitString(elems)
	if err != nil {
		return nil, err
	}
	flag := nodeFlag{hash: hash, gen: cachegen}
	key := compactToHex(kbuf)
	if hasTerm(key) {
		// value node
		val, _, err := rlp.SplitString(rest)
		if err != nil {
			return nil, fmt.Errorf("invalid value node: %v", err)
		}
		return &shortNode{key, append(valueNode{}, val...), flag}, nil
	}
	r, _, err := decodeRef(rest, cachegen)
	if err != nil {
		return nil, wrapError(err, "val")
	}
	return &shortNode{key, r, flag}, nil
}

func decodeFull(hash, elems []byte, cachegen uint16) (*fullNode, error) {
	n := &fullNode{flags: nodeFlag{hash: hash, gen: cachegen}}
	for i := 0; i < 16; i++ {
		cld, rest, err := decodeRef(elems, cachegen)
		if err != nil {
			return n, wrapError(err, fmt.Sprintf("[%d]", i))
		}
		n.Children[i], elems = cld, rest
	}
	val, _, err := rlp.SplitString(elems)
	if err != nil {
		return n, err
	}
	if len(val) > 0 {
		n.Children[16] = append(valueNode{}, val...)
	}
	return n, nil
}

const hashLen = len(common.Hash{})

func decodeRef(buf []byte, cachegen uint16) (node, []byte, error) {
	kind, val, rest, err := rlp.Split(buf)
	if err != nil {
		return nil, buf, err
	}
	switch {
	case kind == rlp.List:
		// 'embedded' node reference. The encoding must be smaller
		// than a hash in order to be valid.
		if size := len(buf) - len(rest); size > hashLen {
			err := fmt.Errorf("oversized embedded node (size is %d bytes, want size < %d)", size, hashLen)
			return nil, buf, err
		}
		n, err := decodeNode(nil, buf, cachegen)
		return n, rest, err
	case kind == rlp.String && len(val) == 0:
		// empty node
		return nil, rest, nil
	case kind == rlp.String && len(val) == 32:
		return append(hashNode{}, val...), rest, nil
	default:
		return nil, nil, fmt.Errorf("invalid RLP string size %d (want 0 or 32)", len(val))
	}
}

// wraps a decoding error with information about the path to the
// invalid child node (for debugging encoding issues).
type decodeError struct {
	what  error
	stack []string
}

func wrapError(err error, ctx string) error {
	if err == nil {
		return nil
	}
	if decErr, ok := err.(*decodeError); ok {
		decErr.stack = append(decErr.stack, ctx)
		return decErr
	}
	return &decodeError{err, []string{ctx}}
}

func (err *decodeError) Error() string {
	return fmt.Sprintf("%v (decode path: %s)", err.what, strings.Join(err.stack, "<-"))
}
