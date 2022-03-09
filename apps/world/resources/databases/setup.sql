CREATE DATABASE sys;
CREATE TABLE pods (id INT, name STRING, status STRING);
INSERT INTO pods (id, name, status) values (1, "pod1", "ok"), (2, "pod2", "not ok"), (3, "pod3", "maybe ok"), (4, "pod4", "i dont know");