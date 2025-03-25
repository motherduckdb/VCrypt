ATTACH 'lineitem_enc_512.db' as demo_lineitem_enc_512;
CREATE SECRET key_2 (
    TYPE VCRYPT,
    TOKEN 'ABCDEFGHIJKLMNOP',
    LENGTH 16
);
CREATE TABLE demo_lineitem_enc_512.lineitem AS
SELECT
    encrypt(l_orderkey, 'key_2') AS l_orderkey,
    encrypt(l_partkey, 'key_2') AS l_partkey,
    encrypt(l_suppkey, 'key_2') AS l_suppkey,
    encrypt(l_linenumber, 'key_2') AS l_linenumber,
    l_quantity,
    l_extendedprice,
    l_discount,
    l_tax,
    l_returnflag,
    l_linestatus,
    encrypt(l_shipdate, 'key_2') AS l_shipdate,
    encrypt(l_commitdate, 'key_2') AS l_commitdate,
    encrypt(l_receiptdate, 'key_2') AS l_receiptdate,
    encrypt(l_shipinstruct, 'key_2') AS l_shipinstruct,
    encrypt(l_shipmode, 'key_2') AS l_shipmode,
    l_comment
FROM lineitem;
CHECKPOINT;
