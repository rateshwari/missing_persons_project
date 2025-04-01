CREATE DATABASE missing_persons_db;

USE missing_persons_db;

CREATE TABLE missing_persons (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100),
  age INT,
  gender ENUM('Male', 'Female', 'Other'),
  last_seen_location VARCHAR(255),
  contact_info VARCHAR(255),
  photo LONGBLOB,
  report_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );

ALTER TABLE missing_persons MODIFY COLUMN photo VARCHAR(255);

SELECT id, report_date FROM missing_persons;

SELECT * FROM missing_persons;

SELECT id, name, photo FROM missing_persons;

DESCRIBE missing_persons;

SELECT id, name, face_encoding FROM missing_persons;

ALTER TABLE missing_persons 
ADD COLUMN status VARCHAR(20);

UPDATE missing_persons SET status = 'Still Missing' WHERE status IS NULL;
