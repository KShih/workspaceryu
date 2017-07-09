from mininet.topo import Topo

class MyTopo( Topo ):
    "Simple topology example."

    def __init__( self,enable_all=True):
        "Create custom topo."
        super(MyTopo,self).__init__()
        Switch0=1
        Switch1=2
        Switch2=3
        Host0=4
        Host1=5
        Host2=6
        # Add hosts and switches
        Host0 = self.addHost( 'h0'  )
        Host1 = self.addHost( 'h1'  )
        Host2 = self.addHost( 'h2'  )
        Switch0 = self.addSwitch( 's0'  )
        Switch1 = self.addSwitch( 's1'  )
        Switch2 = self.addSwitch( 's2'  )
  
        # Add links
        self.addLink( Host0 , Switch0  )
        self.addLink( Switch0 , Switch1  )
        self.addLink( Switch1 , Switch2  )
        self.addLink( Switch2 , Host2  )

topos = { 'mytopo' : ( lambda: MyTopo() ) }
