#!/usr/bin/python
#coding=UTF-8
 
 
import MySQLdb
import connectDB

try:
   db = connectDB.myDB()
 
   # 執行SQL statement
   sql = "SELECT address FROM WhiteList"
   db.cursor.execute(sql)
 
   # 撈取多筆資料
   results = db.cursor.fetchall()
 
   # 迴圈撈取資料
   for row in results:
         print row[0]
 
   # 關閉連線
   db.db.close()

except MySQLdb.Error as e:
    print "%d: %s" % (e.args[0], e.args[1])
