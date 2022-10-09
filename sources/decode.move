// https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/
module rlp::decode {
    use std::vector;

    const ERR_EMPTY: u64 = 0;
    const ERR_INVALID: u64 = 0;

    const TYPE_BYTES: u8 = 0;
    const TYPE_LIST: u8 = 1;

    public fun decode_bytes(rlp: vector<u8>): vector<u8> {
        let _ = rlp;
        return vector::empty()
    }
    public fun decode_bytes_list(rlp: vector<u8>): vector<vector<u8>> {
        let _ = rlp;
        return vector::empty()
    }

    // return: (offset, len, type)
    // type
    // - 0: bytes
    // - 1: bytes_list
    fun decode_length(rlp: &vector<u8>): (u64, u64, u8) {
        let len = vector::length(rlp);
        if (len == 0) {
            assert!(false, ERR_EMPTY);
        };
        let prefix = *vector::borrow(rlp, 0);

        if (prefix <= 0x7f) {
            return (0, 1, TYPE_BYTES)
        } else if (prefix <= 0xb7 && len > ((prefix - 0x80) as u64)) {
            let len = prefix - 0x80;
            return (1, (len as u64), TYPE_BYTES)
        };
        
        let tmp = ((prefix - 0xb7) as u64);
        if (prefix <= 0xb7
            && len > tmp
            && len > tmp + to_integer(&slice(rlp, 1, tmp))
        ) {
            let bytes_len = to_integer(&slice(rlp, 1, tmp));
            return (1 + tmp, bytes_len, TYPE_BYTES)
        };

        let tmp = ((prefix - 0xc0) as u64);
        if (prefix <= 0xf7 && len > tmp) {
            return (1, tmp, TYPE_LIST)
        };

        let tmp = ((prefix - 0xf7) as u64);
        if (prefix <= 0xff
            && len > tmp
            && len > tmp + to_integer(&slice(rlp, 1, tmp))
        ) {
            let list_len = to_integer(&slice(rlp, 1, tmp));
            return (1 + tmp, list_len, TYPE_LIST)
        };

        assert!(false, ERR_INVALID);
        (0,0,0)
    }

    fun slice(vec: &vector<u8>, offset: u64, size: u64): vector<u8> {
        let ret: vector<u8> = vector::empty();
        let i = 0;
        while(i < size) {
            let b = *vector::borrow(vec, offset + i);
            vector::push_back(&mut ret, b);
            i = i + 1;
        };
        return ret
    }

    fun to_integer(bytes: &vector<u8>): u64 {
        let len = vector::length(bytes);
        if (len == 0) {
            assert!(false, ERR_EMPTY);
            return 0 // never evaluated
        } else if (len == 1) {
            let b = *vector::borrow(bytes, 0);
            return (b as u64)
        } else {
            let last = *vector::borrow(bytes, len - 1);
            let left = to_integer(&slice(bytes, 0, len - 1));
            return (last as u64) + left * 256
        }
    }
}