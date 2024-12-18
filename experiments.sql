create or replace table tst(s struct(hi uint64, lo uint32, ctr uint16, val uint128));
insert into tst select {'hi': 0,'lo': range>>15,'ctr': (range&32767)<<1, 'val': (range & 7) * (cast(1 as uint128) << 124) + (range >>2)} s from range(100000000);
from pragma_storage_info('tst') where row_group_id=90;

create or replace table tst(s struct(hi uint64, lo uint32, ctr uint16, val blob));
insert into tst select {'hi': 0,'lo': range>>15,'ctr': (range&32767)<<1,'val':encode('0123456789012345678901234'|| cast(range >> 3 as string))} s from range(100000000);
from tst limit 10;
select len,count(*) from (select octet_length(s.val) len from tst) t group by len;
select cnt,count(*) from (select s.val,count(*) cnt from tst group by 1) group by 1;
select compression,count(*) from pragma_storage_info('tst') where column_path='[0, 4]' group by 1;
from pragma_storage_info('tst') where row_group_id=90;

create or replace table tst(s struct(hi uint64, lo uint32, ctr uint16, val blob));
insert into tst select {'hi': 0,'lo': range>>15,'ctr': (range&32767)<<1,'val':encode('012345678901234567890123456789012345678901234567890123456'|| cast(range >> 4 as string))} s from range(100000000);
from tst limit 10;
select len,count(*) from (select octet_length(s.val) len from tst) t group by len;
select cnt,count(*) from (select s.val,count(*) cnt from tst group by 1) group by 1;
from pragma_storage_info('tst') where row_group_id=90;
select compression,count(*) from pragma_storage_info('tst') where column_path='[0, 4]' group by 1;

create or replace table tst(s struct(hi uint64, lo uint32, ctr uint16, val blob));
insert into tst select {'hi': 0,'lo': range>>15,'ctr': (range&32767)<<1,'val':encode('0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890'|| cast(range >> 5 as string))} s from range(100000000);
select len,count(*) from (select octet_length(s.val) len from tst) t group by len;
select cnt,count(*) from (select s.val,count(*) cnt from tst group by 1) group by 1;
from pragma_storage_info('tst') where row_group_id=90;
select compression,count(*) from pragma_storage_info('tst') where column_path='[0, 4]' group by 1;

create or replace table tst(s struct(hi uint64, lo uint32, ctr uint16, val blob));
insert into tst select {'hi': 0,'lo': range>>15,'ctr': (range&32767)<<1,'val':encode('012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678'|| cast(range >> 6 as string))} s from range(100000000);
select len,count(*) from (select octet_length(s.val) len from tst) t group by len;
select cnt,count(*) from (select s.val,count(*) cnt from tst group by 1) group by 1;
from pragma_storage_info('tst') where row_group_id=90;
select compression,count(*) from pragma_storage_info('tst') where column_path='[0, 4]' group by 1;

create or replace table tst(s struct(val blob));
insert into tst select {'val':encode('01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678990123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234'|| cast(range >> 7 as string))} s from range(100000000);
select len,count(*) from (select octet_length(s.val) len from tst) t group by len;
from pragma_storage_info('tst') where row_group_id=0;

create or replace table tst(s struct(hi uint64, lo uint32, ctr uint16, val blob));
insert into tst select {'hi': 0,'lo': range>>11,'ctr': (range&2047)<<1, 'val':encode('0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567899012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456'|| cast(range >> 8 as string))} s from range(100000000);
select len,count(*) from (select octet_length(s.val) len from tst) t group by len;
select cnt,count(*) from (select s.val,count(*) cnt from tst group by 1) group by 1;
from pragma_storage_info('tst') where row_group_id=90;
select compression,count(*) from pragma_storage_info('tst') where column_path='[0, 4]' group by 1;

