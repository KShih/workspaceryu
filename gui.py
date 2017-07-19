from tkinter import *
import requests

global src_input
global dst_input
global priority_input

class GUIDemo(Frame):
    def __init__(self, master=None):
        Frame.__init__(self, master)
        self.grid()
        self.createWidgets()
  
    def createWidgets(self):
       


        srctxt_input = Label(self)
        srctxt_input["text"] = "Src IP :"
        srctxt_input.grid(row=0,column=0)
        global src_input
        src_input = Entry(self)
        src_input["width"] = 20
        src_input.grid(row=0 , column = 1 , columnspan = 6)
        
        dsttxt_input = Label(self)
        dsttxt_input["text"] = "Dst IP :"
        dsttxt_input.grid(row=1,column=0)
        global dst_input
        dst_input = Entry(self)
        dst_input["width"] = 20
        dst_input.grid(row=1 , column = 1 , columnspan = 6)

        pritxt_input = Label(self)
        pritxt_input["text"] = "Priority :"
        pritxt_input.grid(row=2,column=0)
        global priority_input
        priority_input = Entry(self)
        priority_input["width"] = 20
        priority_input.grid(row=2 , column = 1 , columnspan = 6)        

        btn_add = Button(self)
        btn_add["text"] = "AddEntry"
        btn_add.grid(row=3,column=1)
        btn_add.bind('<Button-1>',add_entry)

        btn_delete = Button(self)
        btn_delete ["text"] = "DenyEntry"
        btn_delete.grid(row=3,column=2)
        btn_delete.bind('<Button-1>',deny_entry) 

        btn_open = Button(self)
        btn_open["text"] = "OpenFirewall"
        btn_open.grid(row=3,column=0)
        btn_open.bind('<Button-1>',open_firewall)

def add_entry(event):
    src =  src_input.get()
    dst =  dst_input.get()
    pri =  priority_input.get()
    rule = {"nw_src" : src ,"nw_dst" : dst ,"nw_proto" : "ICMP","priority" : pri}
    action = requests.post("http://localhost:8080/firewall/rules/all", json= rule)

def deny_entry(event):
    src =  src_input.get()
    dst =  dst_input.get()
    pri =  priority_input.get()
    rule = {"nw_src" : src ,"nw_dst" : dst ,"nw_proto" : "ICMP","priority" : pri ,"actions" : "DENY"}
    action = requests.post("http://localhost:8080/firewall/rules/all", json= rule)

def open_firewall(event):
    action = requests.put("http://localhost:8080/firewall/module/enable/all")

if __name__ == '__main__':
    root = Tk()
    app = GUIDemo(master=root)
    app.mainloop()
