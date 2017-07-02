
# coding: utf-8

# In[4]:

class port_information:
    
    
    def __init__(self,port_num):
        self.port_num = port_num
        self.now = 0
        self.flow = 0
        self.last = 0
        self.blocked_timer = 0
        self.blocked_flag = False
        
    def set_now(self,num):
        self.now = num
   
    def set_last(self,num):
        self.last = num
    
    def set_flow(self,num):
        self.flow = num
    
    def blocked_init(self):
        self.blocked_timer = 0
        self.blocked_flag = False

    def blocked_timer_add(self):
        self.blocked_flag = True
        self.blocked_timer += 1
        
    def set_blocked_flag(self,flag):
        self.blocked_flag = flag
        
