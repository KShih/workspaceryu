class sec:
    def __init__(self):
        self.output_Lock = False
        self.close_Lock = False
        pktin_count = 0

    def set_outputLock(self,Lock):
        self.output_Lock = Lock
    
    def set_closeLock(self,Lock):
        self.close_Lock = Lock

    def set_pktincount(self,num):
        self.pktin_count = num
