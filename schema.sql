-- Copyright 2009 FriendFeed
--
-- Licensed under the Apache License, Version 2.0 (the "License"); you may
-- not use this file except in compliance with the License. You may obtain
-- a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
-- WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
-- License for the specific language governing permissions and limitations
-- under the License.


DROP TABLE IF EXISTS words;
CREATE TABLE words (
    id INT(11) NOT NULL AUTO_INCREMENT,
    hashed_word VARCHAR(256) NOT NULL,
    word VARCHAR(256) NOT NULL UNIQUE,
    total INT(11) NOT NULL,
    PRIMARY KEY (id, hashed_word)
);

DROP TABLE IF EXISTS admins;
CREATE TABLE admins (
    id INT(11) NOT NULL AUTO_INCREMENT,
    email VARCHAR(100) NOT NULL UNIQUE,
    name VARCHAR(100) NOT NULL,
    hashed_password VARCHAR(100) NOT NULL,
    PRIMARY KEY (id)
);

DROP TABLE IF EXISTS sentiment;
CREATE TABLE sentiment (
    id INT(11) NOT NULL AUTO_INCREMENT,
    hashed_url VARCHAR(100) NOT NULL,
    url VARCHAR(100) NOT NULL,
    sentiment VARCHAR(100) NOT NULL,
    PRIMARY KEY (id,hashed_url,url)
);

