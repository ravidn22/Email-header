import pandas as pd
import pypff
ps=pypff.file()
ps.open("F:\Ravi.pst")
import re
ps=ps.get_root_folder()
def pa_folder(base):
    messages=[]
    for fol in base.sub_folders:
        if fol.number_of_sub_folders:
            messages+=pa_folder(fol)

        for mes in fol.sub_messages:
            messages.append({"subject":[mes.subject],"sendby":[mes.sender_name],"header":[mes.transport_headers]})

    return messages

a=pa_folder(ps)

csv_file=pd.DataFrame.from_dict(a[2])

for d in a:
    print(d)
    pd.Series(d,name="a")

    csv_file=csv_file.append(d,ignore_index="False")
files=csv_file["header"]
spf=[]
dkim=[]
dmarc=[]
map=[]
for aut in files:
    try:
        aut=str(aut)
        p=re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
        ipcode=re.findall(p,aut)
        date=re.compile(r'[\d]{1,2} [ADFJMNOS]\w* [\d]{4}')
        dates=re.findall(date,aut)
        print("ip",ipcode[0])
        print("date",dates[0])
        emailExtract=re.compile(("([a-z0-9!#$%&'*+\/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+\/=?^_`"
                                "{|}~-]+)*(@|\sat\s)(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(\.|"
                                "\sdot\s))+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)"))
        email=re.findall(emailExtract,aut)
        print("sender_email",email[2][0])
        email=email[2][0]
        email_domain=email.split("@")[1]
        emaildomin=email_domain.split(".")[0]
        print("domain",emaildomin)
        sendere=aut.find("Authentication-Results")

        header=aut[sendere:]
        emailtrack=re.compile(("([a-z0-9!#$%&'*+\/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+\/=?^_`"
                                "{|}~-]+)*(@|\sat\s)(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(\.|"
                                "\sdot\s))+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)"))
        emails=re.findall(emailtrack,aut)
        emails=emails[0][0]

        spfa=header.find('Received-SPF')+13

        spq=spfa+5
        safe=True
        p=header[spfa:spq]
        if p==' Pass':
            safe=True
        else:
            safe="spf not present"
        spf_Found=header.find("spf")+3
        p=spf_Found+5
        if header[(spf_Found+1):p]=="pass":
            spf.append("safe")
        else:
            spf.append("unsafe")
        dkim_Found=header.find("dkim")+4
        p=dkim_Found+5
        if header[(dkim_Found+1):p]=="pass" :
            dkim.append("safe")
        else:
            dkim.append("unsafe")
        dmarc_Found=header.find("dmarc")+5
        p=dmarc_Found+5
        if header[(dmarc_Found+1):p]=="pass" :
            dmarc.append("safe")
        else:
            dmarc.append("unsafe")

    except :
        safe="None"
        map.append(safe)
        spf.append("None")
        dkim.append("None")
        dmarc.append("None")
csv_file["spf"]=spf
csv_file["dkim"]=dkim
csv_file["dmarc"]=dmarc
print(csv_file)


csv_file.to_csv("F:\information.csv",index=False)
