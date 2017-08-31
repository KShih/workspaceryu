#!/usr/bin/python
#coding=UTF-8

import time,os
import MySQLdb

HOST="120.113.173.84"
USER="root"
PASS="ji3ul42; vul3j;6"
DBNAME="ProjectSDN"

db = MySQLdb.connect(HOST, USER, PASS, DBNAME, charset='utf8')
timefordb = "%s" % time.strftime("%Y%m%d%H%M%S",time.localtime())
cursor = db.cursor()
f = open('5SecPacketInLog.txt','r')

def PushDangerSrc():
    #Get Max no count
    sql = "SELECT MAX(no) FROM (DangerSrc)"
    cursor.execute(sql)
    db.commit()
    result = cursor.fetchone()
    if(result[0] != None):
        num = result[0]
    else:
        num = 0

    for line in open('5SecPacketInLog.txt'):  
        line = f.readline()
        line = line.replace('\n', '')
        sql = "INSERT INTO `DangerSrc`(`no`, `time`, `address`) VALUES ('%d','%s','%s')" % (num,timefordb,line)
        cursor.execute(sql) 
        db.commit()
        num += 1

    f.close()                  
    db.close()
