<?php
    class DB {
        private static $writeDBConnection;
        private static $readDBConnection;

        public static function connectWriteDB() {
            // If DB isn't innitialized, then this if statement gonna do the job
            if(self::$writeDBConnection == null) {
                self::$writeDBConnection = new PDO("mysql:host=localhost;dbname=tasksdb;charset=utf8", "root", "");
                self::$writeDBConnection->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
                self::$writeDBConnection->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
            }

            return self::$writeDBConnection;
        }

        public static function connectReadDB() {
            // If DB isn't innitialized, then this if statement gonna do the job
            if(self::$readDBConnection == null) {
                self::$readDBConnection = new PDO("mysql:host=localhost;dbname=tasksdb;charset=utf8", "root", "");
                self::$readDBConnection->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
                self::$readDBConnection->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
            }

            return self::$readDBConnection;
        }
    }
?>