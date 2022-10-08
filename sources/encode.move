// https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/
module rlp::encode {
    use std::vector;

    const CONST_256_EXP_8: u128 = 18446744073709551616;

    const ERR_TOO_LONG_BYTE_ARRAY: u64 = 0;

    public fun encode_bytes_list(inputs: vector<vector<u8>>): vector<u8> {
        let output = vector::empty();

        let i = 0;
        let len = vector::length(&inputs);
        while(i < len) {
            let next = vector::borrow(&inputs, i);
            let next = encode_bytes(*next);
            vector::append(&mut output, next);
            i = i + 1;
        };

        let left = encode_length(&output, 0xc0);
        vector::append(&mut left, output);
        return left
    }

    public fun encode_bytes(input: vector<u8>): vector<u8> {
        if (vector::length(&input) == 1 && *vector::borrow(&input, 0) < 0x80) {
            return input
        } else {
            let left = encode_length(&input, 0x80);
            vector::append(&mut left, input);
            return left
        }
    }

    fun encode_length(input: &vector<u8>, offset: u8): vector<u8> {
        let len = vector::length(input);
        if (len < 56) {
            return to_byte((len as u8) + offset)
        };
        assert!((len as u128) < CONST_256_EXP_8, ERR_TOO_LONG_BYTE_ARRAY);
        let bl = to_binary(len);
        let len_bl = vector::length(&bl);
        let left = to_byte((len_bl as u8) + offset + 55);
        vector::append(&mut left, bl);
        return left
    }

    fun to_binary(x: u64): vector<u8> {
        if (x == 0) {
            return vector::empty()
        } else {
            let left = to_binary(x / 256);
            let mod = x % 256;
            let right = to_byte((mod as u8));
            vector::append(&mut left, right);
            return left
        }
    }

    fun to_byte(val: u8): vector<u8> {
        let v = vector::empty<u8>();
        vector::push_back(&mut v, val);
        v
    }
}

#[test_only]
module rlp::encode_test {
    use std::vector;
    use rlp::encode::{encode_bytes, encode_bytes_list};

    #[test]
    public fun test_encode() {
        let res = encode_bytes(x"05");
        assert!(x"05" == res, 0);

        let res = encode_bytes(x"");
        assert!(x"80" == res, 0);

        let res = encode_bytes(x"0505");
        assert!(x"820505" == res, 0);

        let res = encode_bytes(x"050505");
        assert!(x"83050505" == res, 0);

        let res = encode_bytes(x"05050505");
        assert!(x"8405050505" == res, 0);

        let res = encode_bytes(x"0505050505");
        assert!(x"850505050505" == res, 0);

        let res = encode_bytes_list(vector::empty());
        assert!(x"c0" == res, 0);

        let res = encode_bytes(x"00");
        assert!(x"00" == res, 0);

        let res = encode_bytes(x"0004");
        assert!(x"820004" == res, 0);

        let res = encode_bytes_list(vector::empty());
        assert!(x"c0" == res, 0);

        let list = vector::empty();
        vector::push_back(&mut list, x"01");
        vector::push_back(&mut list, x"02");
        vector::push_back(&mut list, x"03");
        vector::push_back(&mut list, x"04");
        vector::push_back(&mut list, x"05");
        vector::push_back(&mut list, x"06");
        vector::push_back(&mut list, x"07");
        vector::push_back(&mut list, x"08");
        let res = encode_bytes_list(list);
        assert!(x"C80102030405060708" == res, 0);

        let list = vector::empty();
        vector::push_back(&mut list, x"01");
        vector::push_back(&mut list, x"02");
        vector::push_back(&mut list, x"03");
        vector::push_back(&mut list, x"04");
        vector::push_back(&mut list, x"05");
        let res = encode_bytes_list(list);
        assert!(x"C50102030405" == res, 0);

        let list = vector::empty();
        vector::push_back(&mut list, x"02");
        let res = encode_bytes_list(list);
        assert!(x"C102" == res, 0);

        let res = encode_bytes(x"6162636465666768696a6b6c6d");
        assert!(x"8D6162636465666768696A6B6C6D" == res, 0);

        let res = encode_bytes(x"010203040506");
        assert!(x"86010203040506" == res, 0);

        let res = encode_bytes(x"ffffffffffffffffff");
        assert!(x"89FFFFFFFFFFFFFFFFFF" == res, 0);

        let res = encode_bytes(x"fffffffffffffffff800000000000000001bffffffffffffffffc8000000000000000045ffffffffffffffffc800000000000000001bfffffffffffffffff8000000000000000001");
        assert!(x"B848FFFFFFFFFFFFFFFFF800000000000000001BFFFFFFFFFFFFFFFFC8000000000000000045FFFFFFFFFFFFFFFFC800000000000000001BFFFFFFFFFFFFFFFFF8000000000000000001" == res, 0);
    
        let res = encode_bytes(x"10");
        assert!(x"10" == res, 0);

        let res = encode_bytes(x"0001");
        assert!(x"820001" == res, 0);

        let res = encode_bytes(x"0001");
        assert!(x"820001" == res, 0);

        let list: vector<vector<u8>> = vector::empty();
        vector::push_back(&mut list, x"05");
        vector::push_back(&mut list, x"343434");
        let res = encode_bytes_list(list);
        assert!(x"C50583343434" == res, 0);

        let list: vector<vector<u8>> = vector::empty();
        vector::push_back(&mut list, vector::empty());
        vector::push_back(&mut list, x"343434");
        let res = encode_bytes_list(list);
        assert!(x"C58083343434" == res, 0);

        let list: vector<vector<u8>> = vector::empty();
        vector::push_back(&mut list, x"05");
        let res = encode_bytes_list(list);
        assert!(x"C105" == res, 0);

        let res = encode_bytes(x"222222");
        assert!(x"83222222" == res, 0);

        let list: vector<vector<u8>> = vector::empty();
        vector::push_back(&mut list, x"01");
        vector::push_back(&mut list, x"01");
        vector::push_back(&mut list, x"01");
        let res = encode_bytes_list(list);
        assert!(x"C3010101" == res, 0);

        let list: vector<vector<u8>> = vector::empty();
        vector::push_back(&mut list, x"03");
        let res = encode_bytes_list(list);
        assert!(x"C103" == res, 0);

        let list: vector<vector<u8>> = vector::empty();
        vector::push_back(&mut list, x"01");
        vector::push_back(&mut list, x"02");
        vector::push_back(&mut list, x"03");
        let res = encode_bytes_list(list);
        assert!(x"C3010203" == res, 0);

        let list: vector<vector<u8>> = vector::empty();
        vector::push_back(&mut list, x"01");
        vector::push_back(&mut list, x"02");
        let res = encode_bytes_list(list);
        assert!(x"C20102" == res, 0);

        let list: vector<vector<u8>> = vector::empty();
        vector::push_back(&mut list, x"01");
        let res = encode_bytes_list(list);
        assert!(x"C101" == res, 0);

        let list: vector<vector<u8>> = vector::empty();
        vector::push_back(&mut list, x"");
        let res = encode_bytes_list(list);
        assert!(x"C180" == res, 0);

        let list: vector<vector<u8>> = vector::empty();
        vector::push_back(&mut list, x"03");
        let res = encode_bytes_list(list);
        assert!(x"C103" == res, 0);

        let list: vector<vector<u8>> = vector::empty();
        vector::push_back(&mut list, x"01");
        vector::push_back(&mut list, x"02");
        let res = encode_bytes_list(list);
        assert!(x"C20102" == res, 0);

        let list: vector<vector<u8>> = vector::empty();
        vector::push_back(&mut list, x"01");
        vector::push_back(&mut list, x"02");
        vector::push_back(&mut list, x"03");
        let res = encode_bytes_list(list);
        assert!(x"C3010203" == res, 0);

        let list: vector<vector<u8>> = vector::empty();
        vector::push_back(&mut list, x"01");
        vector::push_back(&mut list, x"02");
        vector::push_back(&mut list, x"03");
        vector::push_back(&mut list, x"04");
        let res = encode_bytes_list(list);
        assert!(x"C401020304" == res, 0);

        let list: vector<vector<u8>> = vector::empty();
        vector::push_back(&mut list, x"01");
        vector::push_back(&mut list, x"");
        let res = encode_bytes_list(list);
        assert!(x"C20180" == res, 0);

        let list: vector<vector<u8>> = vector::empty();
        vector::push_back(&mut list, x"01");
        vector::push_back(&mut list, x"010203");
        let res = encode_bytes_list(list);
        assert!(x"C50183010203" == res, 0);

        let res = encode_bytes(x"ffff");
        assert!(x"82FFFF" == res, 0);

        let res = encode_bytes(x"07");
        assert!(x"07" == res, 0);

        let res = encode_bytes(x"80");
        assert!(x"8180" == res, 0);

        let list: vector<vector<u8>> = vector::empty();
        vector::push_back(&mut list, x"09");
        let res = encode_bytes_list(list);
        assert!(x"C109" == res, 0);

        let list: vector<vector<u8>> = vector::empty();
        vector::push_back(&mut list, x"03030303");
        let res = encode_bytes_list(list);
        assert!(x"C58403030303" == res, 0);

        let list: vector<vector<u8>> = vector::empty();
        vector::push_back(&mut list, x"");
        vector::push_back(&mut list, x"");
        vector::push_back(&mut list, x"05");
        let res = encode_bytes_list(list);
        assert!(x"C3808005" == res, 0);

        let list: vector<vector<u8>> = vector::empty();
        vector::push_back(&mut list, x"01");
        vector::push_back(&mut list, x"040404");
        let res = encode_bytes_list(list);
        assert!(x"C50183040404" == res, 0);
    }
}