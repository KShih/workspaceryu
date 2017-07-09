from tkinter import *
import requests

class GUIDemo(Frame):
    def __init__(self, master=None):
        Frame.__init__(self, master)
        self.grid()
        self.createWidgets()
  
    def createWidgets(self):
        self.btn_add = Button(self)
        self.btn_add["text"] = "AddEntry"
        self.btn_add.grid(row=1,column=0)
        self.btn_add.bind('<Button-1>',go)

        self.txt_input = Label(self)
        self.txt_input["text"] = "Source IP :"
        self.txt_input.grid(row=0,column=0)
        self.fid_input = Entry(self)
        self.fid_input["width"] = 20
        self.fid_input.grid(row=0 , column=1 , columnspan = 6)

def go(event):
      rule = {"nw_src" : "10.0.0.1","nw_dst" : "10.0.0.2","nw_proto" : "ICMP","priority" : "10"}
      set_rule1 = requests.post("http://localhost:8080/firewall/rules/0000000000000001", json= rule)


if __name__ == '__main__':
    root = Tk()
    app = GUIDemo(master=root)
    app.mainloop()
