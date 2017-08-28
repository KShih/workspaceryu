#!/usr/bin/python
#coding=UTF-8
 
HOST="120.113.173.84"
USER="root"
PASS="ji3ul42; vul3j;6"
DBNAME="ProjectSDN"

 
import MySQLdb
try:
   db = MySQLdb.connect(HOST, USER, PASS, DBNAME, charset='utf8')
 
   # 執行SQL statement
   cursor = db.cursor()
   sql = "SELECT address FROM WhiteList"
   cursor.execute(sql)
 
   # 撈取多筆資料
   results = cursor.fetchall()
 
   # 迴圈撈取資料
   for row in results:
         print row[0]
 
   # 關閉連線
   db.close()

except MySQLdb.Error as e:
    print "%d: %s" % (e.args[0], e.args[1])
