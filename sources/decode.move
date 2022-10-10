// https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/
module rlp::decode {
    use std::vector;

    const ERR_EMPTY: u64 = 0;
    const ERR_INVALID: u64 = 1;
    const ERR_NOT_BYTES: u64 = 2;
    const ERR_NOT_LIST: u64 = 3;
    const ERR_NOT_BYTES_LIST: u64 = 4;

    const TYPE_BYTES: u8 = 0;
    const TYPE_LIST: u8 = 1;

    public fun decode_bytes(rlp: &vector<u8>): vector<u8> {
        let len = vector::length(rlp);
        if (len == 0) {
            return vector::empty()
        };

        let output: vector<u8> = vector::empty();
        let (offset, size, type) = decode_length(rlp);
        if (type == TYPE_BYTES) {
            let i = 0;
            while (i < size) {
                let b = *vector::borrow(rlp, offset + i);
                vector::push_back(&mut output, b);
            };
        } else {
            assert!(false, ERR_NOT_BYTES);
        };
        output
    }

    // TODO
    public fun decode_bytes_list(rlp: &vector<u8>): vector<vector<u8>> {
        let len = vector::length(rlp);
        if (len == 0) {
            return vector::empty()
        };

        let output: vector<vector<u8>> = vector::empty();
        let (offset, size, type) = decode_length(rlp);
        if (type == TYPE_BYTES) {
            assert!(false, ERR_NOT_BYTES_LIST);
        } else if (type == TYPE_LIST) {
            let next = decode_bytes(&slice(rlp, offset, size));
            vector::push_back(&mut output, next);
        } else {
            assert!(false, ERR_NOT_BYTES_LIST);
        };

        output
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
        };
        
        let bytes_len = ((prefix - 0x80) as u64);
        if (prefix <= 0xb7 && len > bytes_len) {
            return (1, bytes_len, TYPE_BYTES)
        };
        
        let len_len = ((prefix - 0xb7) as u64);
        let bytes_len = to_integer(&slice(rlp, 1, len_len));
        if (prefix <= 0xb7
            && len > len_len
            && len > len_len + bytes_len
        ) {
            return (1 + len_len, bytes_len, TYPE_BYTES)
        };

        let tmp = ((prefix - 0xc0) as u64);
        if (prefix <= 0xf7 && len > tmp) {
            return (1, tmp, TYPE_LIST)
        };

        let len_len = ((prefix - 0xf7) as u64);
        let list_len = to_integer(&slice(rlp, 1, len_len));
        if (prefix <= 0xff
            && len > len_len
            && len > len_len + list_len
        ) {
            return (1 + len_len, list_len, TYPE_LIST)
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
            return ((last as u64) + left) * 256
        }
    }
}