ATTACH 'lineitem_naive.db' as demo_lineitem_naive;
CREATE SECRET key_2 (
    TYPE VCRYPT,
    TOKEN 'ABCDEFGHIJKLMNOP',
    LENGTH 16
);
CREATE TABLE demo_lineitem_naive.lineitem AS
SELECT
    encrypt_naive(l_orderkey, 'key_2') AS l_orderkey,
    encrypt_naive(l_partkey, 'key_2') AS l_partkey,
    encrypt_naive(l_suppkey, 'key_2') AS l_suppkey,
    encrypt_naive(l_linenumber, 'key_2') AS l_linenumber,
    l_quantity,
    l_extendedprice,
    l_discount,
    l_tax,
    l_returnflag,
    l_linestatus,
    encrypt_naive(l_shipdate, 'key_2') AS l_shipdate,
    encrypt_naive(l_commitdate, 'key_2') AS l_commitdate,
    encrypt_naive(l_receiptdate, 'key_2') AS l_receiptdate,
    encrypt_naive(l_shipinstruct, 'key_2') AS l_shipinstruct,
    encrypt_naive(l_shipmode, 'key_2') AS l_shipmode,
    l_comment
FROM lineitem;
CHECKPOINT;
