## 
## Use the Packet-in's src to calculate the entropy of Packet-IN
##

from math import log
import time,sys

f = open('5SecPacketInLog.txt','r')
ipTotal = 0.0 # the total number of each ip
d = dict()
ef = open('EntropyLog.txt','w')
num_lines = sum(1 for line in open('5SecPacketInLog.txt'))
#ipTotal = 0.0 # the total number of each ip
# Split the ip address & turn into class 
def getKey(f):
    global ipTotal
    str1 = ""
    list1= []
    _input = f.readline()
    list1 = _input.split('.',3)
    if(len(list1) < 3): # the wrong input
        return str1
    else:
        for i in range(0,3):
            str1 += list1[i]
        #print(str1)
        ipTotal += 1
        return str1

# Count the class of each ip
def countIP(num_lines):
    global f
    for i in range(0,num_lines):
        key = getKey(f)
        if(key != ''):
            if key in d:
                d[key] += 1
            else:
                d[key] = 1

# Count the Entropy
def countEnt(ipTotal,d):
    prob = 0.1
    count = 0.0
    entropy = 0.0
    prob_list = []
    for i in range(0,len(d)):
        count = d.values()[i]
        prob = count / ipTotal
        prob_list.append(prob)
    for i in range(0,len(d)):
        entropy -= prob_list[i] * log(prob_list[i], 2 )
    print("entropy: ",entropy)
    ef.write('entropy :' + str(entropy) + '\n')
    return float(entropy)

def cleard():
    global d
    d.clear()

def entropy():
    global f
    global num_lines
    global ipTotal
    global d
    global ef
    d.clear()
    countIP(num_lines)
    countEnt(ipTotal,d)

    ef.close()
    ef = open('EntropyLog.txt','a')
    print d

    #init (by Sean)
    f = open('5SecPacketInLog.txt','r')
    ipTotal = 0.0 # the total number of each ip
    d = dict()
    num_lines = sum(1 for line in open('5SecPacketInLog.txt'))

