"""Exercise the Mac's actual Net-SNMP client against a local synthetic agent."""
import shutil
import socket
import threading
import unittest

from direct_collectors import SNMP, SYS, validate_config


def tlv(tag,value):
    size=len(value)
    length=bytes([size]) if size<128 else bytes([0x82])+size.to_bytes(2,'big')
    return bytes([tag])+length+value


def read_tlv(data,offset=0):
    tag,size=data[offset:offset+2];start=offset;offset+=2
    if size&128:
        count=size&127;size=int.from_bytes(data[offset:offset+count],'big');offset+=count
    return tag,data[offset:offset+size],offset+size,data[start:offset+size]


@unittest.skipUnless(shutil.which('snmpget'),'Net-SNMP is not installed')
class NativeSNMPTests(unittest.TestCase):
    def test_real_client_loads_private_config_and_parses_numeric_output(self):
        agent=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        agent.bind(('127.0.0.1',0));agent.settimeout(3)
        self.addCleanup(agent.close)
        observed=[]
        def serve():
            packet,peer=agent.recvfrom(65535)
            _,outer,_,_=read_tlv(packet)
            _,version,pos,version_tlv=read_tlv(outer)
            _,community,pos,community_tlv=read_tlv(outer,pos)
            observed.append(community.decode())
            _,pdu,_,_=read_tlv(outer,pos)
            _,_,pos,request_id=read_tlv(pdu)
            _,_,pos,_=read_tlv(pdu,pos);_,_,pos,_=read_tlv(pdu,pos)
            _,varbinds,_,_=read_tlv(pdu,pos)
            _,varbind,_,_=read_tlv(varbinds)
            _,_,_,oid=read_tlv(varbind)
            values=tlv(0x30,tlv(0x30,oid+tlv(0x04,b'example-agent')))
            response=tlv(0x30,version_tlv+community_tlv+tlv(0xA2,request_id+tlv(2,b'\0')+tlv(2,b'\0')+values))
            agent.sendto(response,peer)
        worker=threading.Thread(target=serve,daemon=True);worker.start()
        cfg=validate_config('snmp',{'snmp_version':'2c','snmp_port':agent.getsockname()[1]})
        client=SNMP(cfg,{'community':'example-test-community'},'127.0.0.1')
        self.addCleanup(client.close)
        result=client.query([SYS['name']]);worker.join(timeout=3)
        self.assertEqual(observed,['example-test-community'])
        self.assertEqual(result[SYS['name']],'example-agent')


if __name__=='__main__':unittest.main()
