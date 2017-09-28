#!/usr/bin/python
#coding=UTF-8

import time,os
import MySQLdb
import connectDB

timefordb = "%s" % time.strftime("%Y%m%d%H%M%S",time.localtime())
f = open('5SecPacketInLog.txt','r')
db = connectDB.myDB()

def PushDangerSrc():
    #Get Max no count
    global db
    sql = "SELECT MAX(no) FROM (DangerSrc)"
    db.cursor.execute(sql)
    db.db.commit()
    result = db.cursor.fetchone()
    if(result[0] != None):
        num = result[0] +1 
    else:
        num = 0

    for line in open('5SecPacketInLog.txt'):  
        line = f.readline()
        line = line.replace('\n', '')
        sql = "INSERT INTO `DangerSrc`(`no`, `time`, `address`) VALUES ('%d','%s','%s')" % (num,timefordb,line)
        db.cursor.execute(sql) 
        db.db.commit()
        num += 1

    f.close()                  
    db.db.close()
