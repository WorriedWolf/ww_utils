# Eavesdrop Capture

This application is for the express purpose of capturing pcaps for a predefined list of websites.

If you have any questions please contact us at: SOMEEMAIIL@ADDRESS



## Prerequisites

1. Linux, or WIndows laptop
2. tshark installed with sudo/admin privaliges
3. Chrome installed

Before you start the program, it's best to make sure chrome is shut down and that there are no on-going tshark sniffing processes.

When starting the program, this is the first message you will see. This is your opportunity to shut down Chrome. If not, we will kill it. This modal will appear whenever it is appropriate.

![close_chrome](/home/v/Projects/ww_utils/capture/docs/images/close_chrome.png)

Upon opening the application for the first time you will be asked to register.  You will be unable to access the application. 

If it does not take, please try a different user name, otherwise, please contact a worriedwolf admin.

![registration](./images/registration.png)

When you have registered successfully, the full app should appear to you with your username and a GUID that is your id. 

![app_init](images/app_init.png)

Select a website and an action and hit `start sniff`. A new chrome session will start and a keylogfile and pcap file will be created. The sniff is set to timeout after a few seconds but the user may stop the sniff at any point before that by pressing `End Sniff`![sniff_finished](images/sniff_finished.png)

You may either discard or send the data to us and the application will reset itself for the next sniff.

![app_init](images/app_init.png)