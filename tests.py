import sys
import time
import os
import threading

def Test1_1():
    print("Test1.1: Find out the time interval of asking Root or Top")
    tstart = time.time()
    while(1):
        print("%lf"%(time.time() - tstart))
        os.system("host www.google.com")
        time.sleep(61)

def Test1_2():
    print("Test1.2: Prove when the <Root> is asked")
    tstart = time.time()

    #ask the com domain: www.google.com
    print("%lf"%(time.time() - tstart))
    os.system("host www.google.com")
    time.sleep(5)

    #ask the edu domain: www.ucsd.edu
    print("%lf"%(time.time() - tstart))
    os.system("host www.ucsd.edu")
    time.sleep(5)

    #ask the org domain: www.wikipedia.org
    print("%lf"%(time.time() - tstart))
    os.system("host www.wikipedia.org")
    time.sleep(5)

    #ask the net domain: www.sourceforge.net
    print("%lf"%(time.time() - tstart))
    os.system("host www.sourceforge.net")
    time.sleep(5)

    #ask the gov domain: www.nih.gov
    print("%lf"%(time.time() - tstart))
    os.system("host www.nih.gov")

    time.sleep(10)

    #do them again. No <Root> should happend this time

    #ask the com domain: www.google.com
    print("%lf"%(time.time() - tstart))
    os.system("host www.google.com")
    time.sleep(5)

    #ask the edu domain: www.ucsd.edu
    print("%lf"%(time.time() - tstart))
    os.system("host www.ucsd.edu")
    time.sleep(5)

    #ask the org domain: www.wikipedia.org
    print("%lf"%(time.time() - tstart))
    os.system("host www.wikipedia.org")
    time.sleep(5)

    #ask the net domain: www.sourceforge.net
    print("%lf"%(time.time() - tstart))
    os.system("host www.sourceforge.net")
    time.sleep(5)

    #ask the gov domain: www.nih.gov
    print("%lf"%(time.time() - tstart))
    os.system("host www.nih.gov")

    print("finished")

def Test1_3():
    print("Test1.3")
    tstart = time.time()

    #ask the com domain: www.google.com
    print("%lf"%(time.time() - tstart))
    os.system("host www.google.com")
    time.sleep(0.1)
   
    #ask the org domain: www.wikipedia.org
    print("%lf"%(time.time() - tstart))
    os.system("host www.wikipedia.org")
    time.sleep(5)

def Test2_1():
    print("Test2.1: Test Prefeching")
    tstart = time.time()
    i = 5
    while(1):
        if i == 0:
            break
        print("%lf"%(time.time() - tstart))
        os.system("host www.facebook.com")
        time.sleep(60-i)
        print("%lf"%(time.time() - tstart),i)
        os.system("host www.facebook.com")
        time.sleep(60)
        i -= 1
    print("finished")

def Test2_2():
    print("Test2.2: Test Auto Prefeching")
    tstart = time.time()
    print("%lf"%(time.time() - tstart))
    os.system("host www.facebook.com")
    time.sleep(61)
    print("%lf"%(time.time() - tstart))
    print("finished")

def Test2_3():
    print("Test2.3: Test Prefeching More Precisely")
    tstart = time.time()
    i = 0.5
    while(1):
        if i <= 0:
            break
        print("%lf"%(time.time() - tstart))
        os.system("host www.facebook.com")
        time.sleep(57-i)
        print("%lf"%(time.time() - tstart),i)
        os.system("host www.facebook.com")
        time.sleep(60)
        i -= 0.1
    print("finished")

def Test3_1():
    i = 0
    threads = []
    while(1):
        if i == 2:
            break
        newthread = threading.Thread(target=sub_Test3_1, args=(i, ))
        newthread.start()
        threads.append(newthread)
        i += 1

    for thread in threads:
        thread.join()

def sub_Test3_1(number):
    hosts = ['host www.facebook.com', 'host www.google.com']
    print("Test3.1: Test Optimization %d"%(number))
    tstart = time.time()
    time.sleep(1.0 - (time.time() - tstart))
    print("host[%d]:%lf"%(number,(time.time() - tstart)))
    os.system(hosts[number])
    print("host[%d] finished"%(number))

def Test3_2():
    i = 0
    hosts = ['host www.facebook.com', 'host www.google.com']
    tstart = time.time()
    while(1):
        print("host[%d]:%lf"%(i,(time.time() - tstart)))
        os.system(hosts[i])
        print("host[%d] finished"%(i))
        i += 1
        if i == 2:
            break
        time.sleep(10)



if __name__ == "__main__":
    TestName = sys.argv[1]

    locals()[TestName]()