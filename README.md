>> Clone the repo
cd Crypter2
>> Create payload
msfvenom -p windows/x64/messagebox TEXT="Loader Test" TITLE="Success" -f exe -o win.exe 2>/dev/null
>> Run
python3 crypter.py win.exe enc_win.exe
