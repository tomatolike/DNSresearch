from selenium import webdriver
from selenium.webdriver.support.ui import WebDriverWait
import json
import time
from selenium.webdriver.firefox.firefox_profile import FirefoxProfile
import sys
import os
import threading
import random

thread_pool = threading.Semaphore(value=3)

def get_and_analyze_firefox(source,counter,timeout,start_time):
    js = "var performance = window.performance || window.mozPerformance || window.msPerformance || window.webkitPerformance || {}; var network = performance.getEntries() || {}; return network;"
    
    options = webdriver.firefox.options.Options()
    options.add_argument('--headless')

    profile = FirefoxProfile()
    profile.set_preference('browser.cache.disk.enable', False)
    profile.set_preference('browser.cache.memory.enable', False)
    profile.set_preference('browser.cache.offline.enable', False)
    #profile.set_preference('network.cookie.cookieBehavior', 2)
    profile.set_preference('network.dnsCacheEntries', 0)
    profile.set_preference('network.dnsCacheExpiration', 0)
    profile.set_preference('network.dnsCacheExpirationGracePeriod', 0)
    

    driver = webdriver.Firefox(options=options,firefox_profile=profile)
    driver.set_page_load_timeout(timeout)
    
    print("\n%d Getting source %s ...."%(counter,source))
    ok = True
    try:
        driver.get(source)
        data = driver.execute_script(js)
    except:
        ok = False

    driver.delete_all_cookies()
    driver.close()

    if ok:
        block,times = analyze.analyze(data)
        now_time = time.time()
        print("%d There are %d blocks. Time used: "%(counter,block),now_time-start_time)
        return block,times
    else:
        now_time = time.time()
        print("Time Out. Time used: ",now_time-start_time)
        return -1,[]

def get_and_analyze_chrome(source,counter,timeout,start_time):
    js = "var performance = window.performance || window.mozPerformance || window.msPerformance || window.webkitPerformance || {}; var network = performance.getEntries() || {}; return JSON.stringify(network);"
    
    options = webdriver.chrome.options.Options()
    options.add_argument('--headless')
    print("%d Getting source %s ...."%(counter,source))
    ok = True
    
    try:
        #driver = webdriver.Chrome('/usr/lib/chrominum-browser/chromedriver',options=options)
        driver = webdriver.Chrome('/usr/lib/chromium-browser/chromedriver',options=options)
        driver.set_page_load_timeout(timeout)
        driver.get(source)
        #data = driver.execute_script(js)
        #print(data)
    except:
        ok = False
    
    #driver = webdriver.Chrome('/usr/lib/chromium-browser/chromedriver',options=options)
    #driver.set_page_load_timeout(timeout)
    #driver.get(source)
    #data = driver.execute_script(js)
    #print(data)
    

    if ok:
        driver.delete_all_cookies()
        driver.close()

    thread_pool.release()
    sys.exit()
        
    

f = open('websitesout.txt','r')
sources = f.readlines()
#sources = ['https://www.baidu.com','https://www.baidu.com']
f.close()
counter = 0
timeout = 20
limitation = 1000
start_time = time.time()

threads = []

while True:
    s = sources[int(random.random()*997)]
    s = s.replace('\n','')
    #s = 'https://www.baidu.com'
    thread_pool.acquire()
    newthread = threading.Thread(target=get_and_analyze_chrome, args=(s, counter, timeout, start_time, ))
    newthread.start()
    threads.append(newthread)
    #break
    counter += 1
    if counter % 3 == 0:
        for thread in threads:
            thread.join()
        print("stop")
        time.sleep(30)

#for t in threads:
#    t.join()


