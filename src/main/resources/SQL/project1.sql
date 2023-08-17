use project1;

select * from member;
select * from token;

drop table token;
drop table member;

delete from member where user_email = "gminju1665@gmail.com";
delete from token where user_email = "gminju1665@gmail.com";