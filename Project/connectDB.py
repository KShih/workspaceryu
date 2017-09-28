import MySQLdb
import os

class myDB:
    def __init__(self):
        filepath = os.path.abspath("/security.txt")
        fs = open(filepath, 'r')
        db_pass = fs.read().splitlines()
        fs.close()

        self.db = MySQLdb.connect("120.113.173.84", "root", db_pass[0], "ProjectSDN")
        self.cursor = self.db.cursor()

