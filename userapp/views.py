from django.shortcuts import render,redirect
from django.contrib.auth.hashers import make_password
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
User=get_user_model()
import time
from django.shortcuts import render
from rest_framework.response import Response
from rest_framework.views import APIView
from .serializers import UserSerial,VerifySerial
from core.serializer import UserReferral,referserial
from core.models import Current_level,Rank,userRank,wallet,Transactions,membership,Login_history,UserMembership,userWithdrawls,TicketModel,UserReferral,plansmodel,levels,Emailservice,newsmodel,appsettings,UserAddressDetail,levelincome,userunlockedlevel,UserStaking,Ptransfer,gallaryimages,FarmingRoiLogs,StakingRoiLogs,youtubevideo,businesslogs,usercofounderclub,cofounderclub,ManageRoi,WithdrawSettingModel
from django.contrib.auth.hashers import make_password
import jwt
from datetime import datetime
from datetime import  timedelta
from django.conf import settings
from rest_framework import status
from .utils import send_email,send_otp
from random import randint as rd
from .models import Verify
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate
from django.http import JsonResponse
import os
from dotenv import load_dotenv
from pathlib import Path
import jwt
KEYS = getattr(settings, "KEY_", None)
import requests

from dateutil.relativedelta import relativedelta

def getdata():
    api=r'https://api.dex-trade.com/v1/public/ticker?pair=ALPUSDT'
    data=requests.get(url=api)
    data=data.json()
    return data



def home(request,pk=None):
    if request.session.has_key('email')  and request.session.get('role') == 'user'  and request.session.has_key('token'):  
        try:
            d = jwt.decode(request.session.get('token'), key=KEYS, algorithms=['HS256'])
            if d.get('email')!=request.session.get('email'):
                return redirect('../../../')
        except:
            try:
                del request.session['email']
                del request.session['role']
                del request.session['token']
            except:
                pass
            return redirect('../../../')
        try:
   
            user=User.objects.get(email=request.session.get('email'))
            if user.verified_at=='True' and user.status=='1':
                
                ref_link=invite(user.referal_code)  
                 
                    #tabs        
                total_withdrawls=sum([float(i.amount) for i in userWithdrawls.objects.filter(user_id=user.id,type='0',status='1')])

                staking_roi=StakingRoiLogs.objects.filter(user_id=user.id,status='1')

                smart_contract=WithdrawSettingModel.objects.get(id=1)
                total_staking_roi=sum([float(i.roi_recieved) for i in UserStaking.objects.filter(user_id=user.id,status='1')])


                farming_roi=FarmingRoiLogs.objects.filter(user_id=user.id)
                total_farming_roi=sum([float(i.roi_recieved) for i in  UserMembership.objects.filter(user_id=user.id,status='1')])

                staking_balance=sum([float(i.amount) for i in UserStaking.objects.filter(user_id=user.id,status='1')])
                farming_balance=sum([float(i.amount) for i in UserMembership.objects.filter(user_id=user.id,status='1')])

                userwallet=wallet.objects.get(user_id=user.id) 
                user_refferals=User.objects.filter(referal_by=user.referal_code)
                total_user_refferals=len(user_refferals)
                usr_rf=UserReferral.objects.filter(parent_id=user.id)
                refferal_income=sum([float(i.refferal_income) for i in usr_rf])
                if user.paid_members=='False':
                    m='False'
                else:
                    m='True'

                team=[]
                child_id=[i.referal_code for i in user_refferals]
                if len(child_id)>0:
                    while True:
                        team.extend(child_id)
                        child_id=[i.referal_code for i in User.objects.filter(referal_by__in=child_id)]
                        if len(child_id)==0:
                            break
             
                team=len(team)
                    
                
                
               
               
                currnet_date=str(datetime.utcnow())[:10]
    
                newsdata=newsmodel.objects.filter(datato__gt=currnet_date,status='True',date__lte=currnet_date)
                try:
                    appdetail=appsettings.objects.get(status='1')
                except:
                    appdetail=None

                ytv=youtubevideo.objects.filter(type='1',status='1')
                video_data=youtubevideo.objects.filter(type='2',status='1')
                print(video_data)
                if len(ytv)>0:
                    ytv=ytv[0]
                else:
                    ytv=None
                try:
                    alpdata=getdata().get('data').get('last')
                except:
                    alpdata=None
                total_income=float(total_farming_roi)+float(total_staking_roi)+float(refferal_income)

                # print(total_income)
                
                
                return render(request,'userpages/home.html',{'total_income':total_income,
                                                             'userwallet':userwallet,
                                                             'user_refferals':user_refferals,
                                                            'total_staking_roi':total_staking_roi,
                                                            'total_farming_roi':total_farming_roi,
                                                             'total_user_refferals':total_user_refferals,
                                                             'total_withdrawls':total_withdrawls,
                                                             'u':user.email,
                                                             'last':alpdata,
                                                             'ref_link':ref_link,
                                                             'newsdata':newsdata,
                                                            'size':len(newsdata),
                                                            'appdetail':appdetail,
                                                            'ytv':ytv,
                                                            'farming_balance':farming_balance,
                                                            'staking_balance':staking_balance,
                                                            'refferal_income':refferal_income,
                                                            'team':team,
                                                            'staking_roi':staking_roi,
                                                            'farming_roi':farming_roi,
                                                            'userdata':user,
                                                            'video_data':video_data,
                                                            'm':m,
                                                            'smart_contract':smart_contract
                                                             })
            else:
                del request.session['email']
                del request.session['role']
                return redirect('../../../')
                                   
        except:
            del request.session['email']
            del request.session['role']
            return redirect('../../../')
            

            
    else:
        return redirect('../../../')

def register(request,pk=None):   
    
    if request.session.get('role')=='user':
        return redirect("../../dashboard")
    elif request.session.get('role')=='admin':
        return redirect("../../admin/dashboard")

    if pk is not None:
        print(pk)
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        return render(request,'userpages/register_2.html',{'userdata':pk,'appdetail':appdetail})

    if request.method=='POST':
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        
        email=request.POST.get('email')
        first_name=request.POST.get('firstname')
        last_name=request.POST.get('lastname')
        password=request.POST.get('password')
        confirmpassword=request.POST.get('confirmpassword')
        referral = request.POST.get('referral')
        
        if password == confirmpassword:
            password=make_password(password)
        else:
            return render(request,'userpages/register_2.html',{'message4':"Password & confirm passowrd incorrect",'appdetail':appdetail})

        try:
            usr=User.objects.get(email=email)
            if usr is not None:
                verified=usr.verified_at
                if verified=='False':
                    usr.delete()
                else:
                    return render(request,'userpages/register_2.html',{'message':'Email already registed','appdetail':appdetail})
        except:
            pass
        payload_ = {'email': email, 'exp': datetime.utcnow() + timedelta(minutes=2)}

        token = jwt.encode(payload=payload_,
                                   key=KEYS
                                   )
        if referral=='':
            User.objects.create(username='BS'+str(int(time.time()))+'T',email=email,first_name=first_name,last_name=last_name,password=password,remember_token=token)
        else:
            try:
                ob=User.objects.get(referal_code=referral)
                if ob.verified_at=='True' and ob.status=='1':
                    User.objects.create(username='BS'+str(int(time.time()))+'T',email=email,first_name=first_name,last_name=last_name,password=password,referal_by=referral,remember_token=token)
            except:
                return render(request,'userpages/register_2.html',{'message3':'Refferal Code Not Valid','appdetail':appdetail})
        request.session['email']=email
        emailsettings=Emailservice.objects.get(status='1')
        path = Path("./config.env")
        load_dotenv(dotenv_path=path)
        SITE_URL = os.getenv('SITE_URL')
        url=f'{SITE_URL}/verify/{token}'
        send_otp(email,url,emailsettings)
        return render(request,'userpages/verify_page.html')    
    try:
        appdetail=appsettings.objects.get(status='1')
    except:
        appdetail=None 
    return render(request,'userpages/register_2.html',{'appdetail':appdetail})

def verifyregister(request,pk=None):
    if pk is not None:
        print("hello")
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        try:
            d = jwt.decode(pk, key=KEYS, algorithms=['HS256'])
            em = d.get('email')
            User = get_user_model()
            usr = User.objects.get(email=em)
            remember_token=usr.remember_token
            
            if remember_token!=pk:
                return render(request,'userpages/register_2.html',{'appdetail':appdetail,'message1':'Invalid Link'})
            else:
                usr.verified_at = 'True'
                usr.status='1'
                usr.save()
                request.session['email']=usr.email
                request.session['role']=usr.role
                payload_ = {'email': em, 'exp': datetime.utcnow() + timedelta(days=1)}

                token = jwt.encode(payload=payload_,
                                   key=KEYS
                                   )
                request.session['token']=token
                usr= User.objects.get(email=em)
                ip=request.META.get('HTTP_X_FORWARDED_FOR')
                if ip:
                    ip=ip.split(',')[0]
                else:
                    ip=ip = request.META.get('REMOTE_ADDR')
                    
                Login_history.objects.create(user_id=usr,ip_location=ip)
                
                return redirect('../../../dashboard')
                
        except:
            return render(request,'userpages/register_2.html',{'appdetail':appdetail,'message1':'Invalid Expired'}) 
    else:
        return redirect('../../register')
    
def reset_password(request,pk=None):
    if pk is not None:
        
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        try:
            d = jwt.decode(pk, key=KEYS, algorithms=['HS256'])
            print('d-->',d)
            em = d.get('email')
            print('email-->',em)
            User = get_user_model()

            usr = User.objects.get(email=em)
            print("user -->",usr)
            remember_token=usr.remember_token
            print(usr.verified_at,usr.status,usr.role)
            if usr.verified_at!='True' or usr.status!='1' or usr.role!='user':
            
                return render(request,'userpages/forgot_password_2.html',{'appdetail':appdetail,'message':'Invalid Email'})
            elif remember_token!=pk :
            
                return render(request,'userpages/forgot_passowrd_2.html',{'appdetail':appdetail,'message':'Invalid Link'})
            
                
            payload_ = {'email': em,'exp': datetime.utcnow() + timedelta(minutes=30)}

            token = jwt.encode(payload=payload_,
                                   key=KEYS
                                   )
            
                
            if usr.role=='user':
                return render(request,'userpages/new_password_meta.html',{'em':em,'token':token})
                
                
        except:
            print('expect part')
            return render(request,'userpages/forgot_password_2.html',{'appdetail':appdetail,'message':'link Expired'}) 
    else:
        print('else part')
        return redirect('../../forgot')

def newpassword(request):
    if request.method=='POST':
        print("hello")
        email=request.POST.get('email')
        token=request.POST.get('token')
        new_password=request.POST.get('new_password')
        confirm_password=request.POST.get('confirm_password')
        print(email,token,new_password,confirm_password)
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            print(d)
            if d.get('email')!=email:
                return redirect('../../../')
        except:
            return redirect('../../../')
        
        if confirm_password!=new_password:
            payload_ = {'email': email,'exp': datetime.utcnow() + timedelta(minutes=30)}

            token = jwt.encode(payload=payload_,
                                   key=KEYS
                                   )

            return render(request,'userpages/new_password_meta.html',{'em':email,'token':token,'message':'New Password and confirm Password Mismatch'})
        else:
            try:
                usr=User.objects.get(email=email)
            except:
                payload_ = {'email': email}

                token = jwt.encode(payload=payload_,
                                   key=KEYS
                                   )

                return redirect('../../../')
            if usr.status!='1' and usr.verified_at!='True':
                

                return render(request,'userpages/forgot_password_2.html.html',{'message':'Account Not Found'})
            usr.password=make_password(new_password)
            usr.save()
            request.session['email']=email
            request.session['role']=usr.role
            payload_ = {'email': email,'exp': datetime.utcnow() + timedelta(days=1)}

            token = jwt.encode(payload=payload_,
                                   key=KEYS
                                   )
            request.session['token']=token
            print("hello")
            if usr.role=='user':
                print('Hey')
                return redirect('../../../dashboard')
            elif usr.role=='admin':
                return redirect('../../../admin/dashboard')

    else:
        return redirect('../../../')
           
def forgot(request):
    try:
        appdetail=appsettings.objects.get(status='1')
    except:
        appdetail=None
    
    if request.method=='POST':
        email=request.POST.get('email')
        try:
            User=get_user_model()

            usr=User.objects.get(email=email)
            act=usr.verified_at
            if act=='False' or usr.status=='0' or usr.role=='admin':
                return render(request,"userpages/forgot_password_2.html",{'message3':'Invalid Email Address','appdetail':appdetail})
        except:
            return render(request,"userpages/forgot_password_2.html",{'message3':'Invalid Email Address','appdetail':appdetail})
     
        payload_ = {'email': email, 'exp': datetime.utcnow() + timedelta(minutes=2)}

        token = jwt.encode(payload=payload_,
                                   key=KEYS
                                   )
        usr.remember_token=token
        usr.created_at=int(time.time())
        usr.save()
        request.session['email']=email
        request.session['reset']='True'
        emailsettings=Emailservice.objects.get(status='1')
        path = Path("./config.env")
        load_dotenv(dotenv_path=path)
        SITE_URL = os.getenv('SITE_URL')
        url=f'{SITE_URL}/reset_password/'+token
        send_otp(email,url,emailsettings)
        return render(request,"userpages/verify_page.html")
    return render(request,"userpages/forgot_password_2.html",{'appdetail':appdetail})

def otp(request):
    try:
        appdetail=appsettings.objects.get(status='1')
    except:
        appdetail=None
    if request.method == "POST":
        otp = request.POST.get('otp')
        email = request.session.get('email')
        User=get_user_model()
        usr=User.objects.get(email=email)
        otp_=usr.remember_token
        id=usr.id
        try:
            vr=Verify.objects.get(id=id)
        except:
            return Response({'status':False,'message':'otp not registered'},status=status.HTTP_400_BAD_REQUEST)
        start=vr.start
        start=int(start)
        end = datetime.now()
        end= int(end.timestamp())
        if (end-start)<180:
            if str(otp_)==str(otp):
                uname = usr.username
                payload_ = {'email': email, 'username': uname, 'exp': datetime.utcnow() + timedelta(days=1)}

                token = jwt.encode(payload=payload_,
                                   key=KEYS
                                   )
                return render(request,"userpages/change_password.html",{'message':'OTP matched','appdetail':appdetail})
            else:
                return Response({'status':False,'message':'Invalid Otp'},status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'status':False,'message':'Otp expired'},status=status.HTTP_401_UNAUTHORIZED)
        
    return render(request,"userpages/change_password.html",{'appdetail':appdetail})

def change(request):
    try:
        appdetail=appsettings.objects.get(status='1')
    except:
        appdetail=None
    if request.method=='POST':
        em=request.session.get('email')
        password=request.POST.get('newpassword')
        confpassword=request.POST.get('confirmpassword')
        if password==confpassword:
            User = get_user_model()
            usr=User.objects.get(email=em)         
            usr.password=make_password(password)
            usr.save()
            return render(request,'userpages/login_2.html',{'message6':'Password changed successfully , now login','appdetail':appdetail})
        else:
            return render(request,'userpages/change_password.html',{'message2':'New password & Confirm password did not matched','appdetail':appdetail})
        
        
def loginpage(request):


    
    if request.session.get('role')=='user':
        return redirect("../../dashboard")
    elif request.session.get('role')=='admin':
        return redirect("../../admin/dashboard")
    else:
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        if request.method=='POST': 
           
            em=request.POST.get('email')
            ps=request.POST.get('password')
            
            
            try:
                username=User.objects.get(email=em).username
            except:
                return render(request,'userpages/login_2.html',{'message':'Incorrect Email','appdetail':appdetail})
            usr=authenticate(email=em,password=ps)
            if usr is not None:
            
                if usr.role == 'admin' : 
                    if usr.verified_at=='True' and usr.status=='1':          
                        request.session['email']=em
                        request.session['role']=usr.role
                        payload_ = {'email': em,'exp': datetime.utcnow() + timedelta(days=1)}

                        token = jwt.encode(payload=payload_,
                                   key=KEYS,
                                   )
                        request.session['token']=token
                        ip=request.META.get('HTTP_X_FORWARDED_FOR')
                        if ip:
                            ip=ip.split(',')[0]
                        else:
                            ip=ip = request.META.get('REMOTE_ADDR')
                    
                        Login_history.objects.create(user_id=usr,ip_location=ip,login_time=datetime.utcnow())
               
                        return redirect('../../../admin/dashboard')
                elif usr.role == 'user':  
                    if usr.verified_at=='True' and usr.status=='1':     
                        request.session['email']=em
                        request.session['role']=usr.role    
                        usr= User.objects.get(email=em) 
                        payload_ = {'email': em,'exp': datetime.utcnow() + timedelta(days=1)}

                        token = jwt.encode(payload=payload_,
                                   key=KEYS
                                   )
                        request.session['token']=token            
                        ip=request.META.get('HTTP_X_FORWARDED_FOR')
                        if ip:
                            ip=ip.split(',')[0]
                        else:
                            ip=ip = request.META.get('REMOTE_ADDR')
                    
                        Login_history.objects.create(user_id=usr,ip_location=ip,login_time=datetime.utcnow())
                
                        return redirect('../../../dashboard')
                
                else:
                    return render(request, 'userpages/login_2.html',
                            {'message':'Email or password incorrect','appdetail':appdetail})
            
        return render(request,'userpages/login_2.html',{'appdetail':appdetail})

 

def loginviagoogle(request):
    try:
        appdetail=appsettings.objects.get(status='1')
    except:
        appdetail=None
    try:
       
        print(request.user)
        usr=User.objects.get(username=request.user.username,password=request.user.password)
        usr.verified_at='True'
        usr.save()
        request.session['email']=usr.email
        request.session['role']=usr.role

        ip=request.META.get('HTTP_X_FORWARDED_FOR')
        if ip:
            ip=ip.split(',')[0]
        else:
            ip=ip = request.META.get('REMOTE_ADDR')
                    
        Login_history.objects.create(user_id=usr,ip_location=ip,login_time=datetime.utcnow())
        
        return redirect('../../../../dashboard')
    except:
        pass
    return render(request,'userpages/login_2.html',{'appdetail':appdetail})  


def myprofile(request):
    if request.session.has_key('email')  and request.session.get('role') == 'user'  and request.session.has_key('token'):  
        try:
            d = jwt.decode(request.session.get('token'), key=KEYS, algorithms=['HS256'])
            if d.get('email')!=request.session.get('email'):
                return redirect('../../../')
        except:
            try:
                del request.session['email']
                del request.session['role']
                del request.session['token']
            except:
                pass
                return redirect('../../../')
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        usr=User.objects.get(email=request.session.get('email'))
        smart_contract=WithdrawSettingModel.objects.get(id=1)
        ref_link=invite(usr.referal_code) 
        currnet_date=str(datetime.utcnow())[:10]
    
        newsdata=newsmodel.objects.filter(datato__gt=currnet_date,status='True',date__lte=currnet_date) 
        try:
            alpdata=getdata().get('data').get('last')
        except:
            alpdata=None
        return render(request,'userpages/myprofile.html',{'userdata':usr,
                                                          'ref_link':ref_link,
                                                          'newsdata':newsdata,
                                                            'size':len(newsdata),
                                                            'appdetail':appdetail,
                                                            'last':alpdata,
                                                            'u':request.session.get('email'),
                                                            'smart_contract':smart_contract}),


    else:
        return redirect("../../../")

def walletview(request):
    if request.session.has_key('email')  and request.session.get('role') == 'user'  and request.session.has_key('token'):  
        try:
            d = jwt.decode(request.session.get('token'), key=KEYS, algorithms=['HS256'])
            if d.get('email')!=request.session.get('email'):
                return redirect('../../../')
        except:
            try:
                del request.session['email']
                del request.session['role']
                del request.session['token']
            except:
                pass
            return redirect('../../../')
        message=None
        message1=None
        try:
            alpdata=getdata().get('data').get('last')
        except:
            alpdata=None
        smart_contract=WithdrawSettingModel.objects.get(id=1)
        if request.method=='POST':
            if 'withdraw' in request.POST:
                amount=request.POST.get('amount')
                address=request.POST.get('address')
                user_id=User.objects.get(email=request.session.get('email'))
                wallet_id=wallet.objects.get(user_id=user_id.id)
                if float(wallet_id.avaliable_balance)>=float(amount) :
                    wallet_id.avaliable_balance=float(wallet_id.avaliable_balance)-float(amount)
                    wallet_id.save()
                    userWithdrawls.objects.create(user_id=user_id,wallet_id=wallet_id,amount=amount,address=address,type='0')
                    message='Request Created Successfully'
                else:
                    message1='Insufficient Balance'
            elif 'deposite' in request.POST:
                amount=request.POST.get('amount')
                # address=request.POST.get('address')
                user_id=User.objects.get(email=request.session.get('email'))
                wallet_id=wallet.objects.get(user_id=user_id.id)
                userWithdrawls.objects.create(user_id=user_id,wallet_id=wallet_id,amount=amount,type='1')

        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        id=User.objects.get(email=request.session.get('email')).id
        user=User.objects.get(id=id)
        if user.paid_members=='False':
            m='False'
        else:
            m='True'
        if True:
            user=User.objects.get(email=request.session.get('email'))
            if user.verified_at=='True' and user.status=='1':
                if user.paid_members=='True':
                    ref_link=invite(user.referal_code)    
                else:
                    ref_link=None  
            try:
                userwallet=wallet.objects.get(user_id=id)
                total=userwallet.avaliable_balance+userwallet.freezed_balance
                usr=User.objects.get(email=request.session.get('email'))
                userlevel=Current_level.objects.get(user_id=usr)
                level_points=int(userlevel.points)
                
            except:
                userwallet=0
                total=0
                level_points=0

            currnet_date=str(datetime.utcnow())[:10]
            incomedata=userWithdrawls.objects.filter(wallet_id=userwallet.id,type='1')
            outcomedata=userWithdrawls.objects.filter(wallet_id=userwallet.id,type='0')
            newsdata=newsmodel.objects.filter(datato__gt=currnet_date,status='True',date__lte=currnet_date)
            return render(request,'userpages/wallet.html',{'wallet':userwallet,
                                                        'total':total,
                                                        'userdata':usr,'points':level_points,
                                                        'ref_link':ref_link,
                                                        'newsdata':newsdata,
                                                        'size':len(newsdata),
                                                        'appdetail':appdetail,
                                                        'u':request.session.get('email'),
                                                        'incomedata':incomedata,
                                                        'outcomedata':outcomedata,
                                                        'message':message,
                                                        'last':alpdata,
                                                        'message1':message1,
                                                        'm':m,
                                                        'smart_contract':smart_contract})
    else:
        return redirect("../../../")

def deposit(request):
    if request.session.has_key('email')  and request.session.get('role') == 'user'  and request.session.has_key('token'):  
        try:
            d = jwt.decode(request.session.get('token'), key=KEYS, algorithms=['HS256'])
            if d.get('email')!=request.session.get('email'):
                return redirect('../../../')
        except:
            try:
                del request.session['email']
                del request.session['role']
                del request.session['token']
            except:
                pass
            return redirect('../../../')
        message=None
        message1=None
        try:
            alpdata=getdata().get('data').get('last')
        except:
            alpdata=None
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        user_id=User.objects.get(email=request.session.get('email'))
        user_wallet=wallet.objects.get(user_id=user_id.id)
        smart_contract=WithdrawSettingModel.objects.get(id=1)

        currnet_date=str(datetime.utcnow())[:10]
        newsdata=newsmodel.objects.filter(datato__gt=currnet_date,status='True',date__lte=currnet_date)

        if request.method=='POST':
            if 'addfund' in request.POST:
                currency=request.POST.get('currency')
                amount=request.POST.get('amount')
                return render(request,'userpages/depositsection.html',{'appdetail':appdetail,
                                                                       'u':request.session.get('email'),
                                                                       'newsdata':newsdata,
                                                                       'walletdata':user_wallet,
                                                                       'message':message,
                                                                       'message1':message1,
                                                                       'currency':currency,
                                                                       'last':alpdata,
                                                                       'amount':amount,
                                                                       'smart_contract':smart_contract})



        
        incomedata=userWithdrawls.objects.filter(user_id=user_id.id,wallet_id=user_wallet.id,type='1')
        
        return render(request,'userpages/deposit.html',{'appdetail':appdetail,
                                                    'u':request.session.get('email'),
                                                    'newsdata':newsdata,
                                                    'walletdata':user_wallet,
                                                    'incomedata':incomedata,
                                                    'message':message,
                                                    'last':alpdata,
                                                    'message1':message1,
                                                    'smart_contract':smart_contract})
    else:
        return redirect('../../../')

def withdrawal(request): 
    if request.session.has_key('email')  and request.session.get('role') == 'user'  and request.session.has_key('token'):  
        try:
            d = jwt.decode(request.session.get('token'), key=KEYS, algorithms=['HS256'])
            if d.get('email')!=request.session.get('email'):
                return redirect('../../../')
        except:
            try:
                del request.session['email']
                del request.session['role']
                del request.session['token']
            except:
                pass
            return redirect('../../../')
        message=None
        message1=None
        try:
            alpdata=getdata().get('data').get('last')
        except:
            alpdata=None
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        currnet_date=str(datetime.utcnow())[:10]
        newsdata=newsmodel.objects.filter(datato__gt=currnet_date,status='True',date__lte=currnet_date)
        user_id=User.objects.get(email=request.session.get('email'))
        user_wallet=wallet.objects.get(user_id=user_id.id)
        smart_contract=WithdrawSettingModel.objects.get(id=1)
        if request.method=='POST':
            if 'withdraw' in request.POST:
                currency=request.POST.get('currency')
                amount=request.POST.get('amount')
                address=request.POST.get('address')
                print(currency)
                fees=WithdrawSettingModel.objects.get(id=1).fees
                final_fees=(float(fees)*float(amount))/100
                final_amount=float(amount)-final_fees
                
                if float(user_wallet.avaliable_balance)>=float(amount) :
                    user_wallet.avaliable_balance=float(user_wallet.avaliable_balance)-float(amount)
                    user_wallet.save()
                    userWithdrawls.objects.create(user_id=user_id,wallet_id=user_wallet,amount=final_amount,fees=final_fees,address=address,currency=currency,type='0')
                    message='Request Created Successfully'
                else:
                    message1='Insufficient Balance'
        outcomedata=userWithdrawls.objects.filter(user_id=user_id.id,wallet_id=user_wallet.id,type='0')
        return render(request,'userpages/withdrawal.html',{'appdetail':appdetail,
                                                           'message':message,
                                                           'message1':message1,
                                                           'newsdata':newsdata,
                                                           'walletdata':user_wallet,
                                                           'last':alpdata,
                                                           'outcomedata':outcomedata,
                                                           'smart_contract':smart_contract})
    else:
        return redirect('../../../')

def memberships(request,pk=None):
    if request.session.has_key('email')  and request.session.get('role') == 'user'  and request.session.has_key('token'):  
        try:
            d = jwt.decode(request.session.get('token'), key=KEYS, algorithms=['HS256'])
            if d.get('email')!=request.session.get('email'):
                return redirect('../../../')
        except:
            try:
                del request.session['email']
                del request.session['role']
                del request.session['token']
            except:
                pass
            return redirect('../../../')
        message=None
        try:
            alpdata=getdata().get('data').get('last')
        except:
            alpdata=None
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        id=User.objects.get(email=request.session.get('email')).id
        usr=User.objects.get(id=id)     
        message=None
        smart_contract=WithdrawSettingModel.objects.get(id=1)
        ref_link=invite(usr.referal_code)  
     
        
        currnet_date=str(datetime.utcnow())[:10]
        obj=membership.objects.filter(status='1')
      
        newsdata=newsmodel.objects.filter(datato__gt=currnet_date,status='True',date__lte=currnet_date)
        return render(request,'userpages/membership.html',{'data':obj,'message':message,
                                                               'ref_link':ref_link,'appdetail':appdetail,
                                                               'u':request.session.get('email'),
                                                               'newsdata':newsdata,
                                                               'last':alpdata,
                                                               'size':len(newsdata),
                                                               'smart_contract':smart_contract
                                                               })
       
    else:
        return redirect("../../../")
        # if request.method =='POST':
        #     plan_id=request.POST.get('id')
        #     try:
        #         obj=UserMembership.objects.get(user_id=usr.id,plan_id=plan_id,status='1')
        #         message='Already Have This Plan'
        #     except:       
        #         plan=membership.objects.get(id=plan_id)
        #         data=datetime.utcnow()
              
                
                  
        #         print(plan.plan_id.id)   
        #         if str(plan.plan_id.id)=='1':
        #             print("hello")
        #             create=UserMembership.objects.create(user_id=usr,plan_id=plan,amount=plan.amount,status='1') 
                    
        #             #matrixplan(create)
        #         elif plan.plan_id.id=='2':
        #             try:
        #                 ob=UserMembership.objects.filter(user_id=usr.id)
        #                 if len(UserMembership)>0:
        #                     #fastrackplan(create)
        #                 else:
        #                     message='Need To Activate First Matrix Plan'
        #             except:
        #                 pass
                    
                
                #Transaction History Here
        # currnet_date=str(datetime.utcnow())[:10]
    
        # newsdata=newsmodel.objects.filter(datato__gt=currnet_date,status='True',date__lte=currnet_date)
        # member=membership.objects.filter(status='1',plan_id=plan_id)
        # return render(request,'userpages/membership.html',{'data':member,'message':message,
        #                                                    'ref_link':ref_link,
        #                                                    'newsdata':newsdata,
        #                                                     'size':len(newsdata),'appdetail':appdetail,'appdetail':appdetail,
        #                                                     'u':request.session.get('email'),
        #                                                     'message':message})
       


def transactions(request):
    if request.session.has_key('email')  and request.session.get('role') == 'user'  and request.session.has_key('token'):  
        try:
            d = jwt.decode(request.session.get('token'), key=KEYS, algorithms=['HS256'])
            if d.get('email')!=request.session.get('email'):
                return redirect('../../../')
        except:
            try:
                del request.session['email']
                del request.session['role']
                del request.session['token']
            except:
                pass
            return redirect('../../../')
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        try:
            alpdata=getdata().get('data').get('last')
        except:
            alpdata=None
        id=User.objects.get(email=request.session.get('email')).id
        usr=User.objects.get(id=id) 
        currnet_date=str(datetime.utcnow())[:10]
        smart_contract=WithdrawSettingModel.objects.get(id=1)
    
        newsdata=newsmodel.objects.filter(datato__gt=currnet_date,status='True',date__lte=currnet_date) 
        if usr.paid_members=='False':
            #return redirect('../../plan') 
            pass
          
        if True:
            user=User.objects.get(email=request.session.get('email'))
            if user.verified_at=='True' and user.status=='1':
                if user.paid_members=='True':
                    ref_link=invite(user.referal_code)    
                else:
                    ref_link=None  
            try:
                wallet_id=wallet.objects.get(user_id=usr.id).id
                transaction_history=Transactions.objects.get(wallet_id=wallet_id)
                return render(request,'userpages/transactions.html',{'userdata':id,
                                                                 'transactions':transaction_history,
                                                                 'ref_link':ref_link,
                                                                 'newsdata':newsdata,
                                                                    'size':len(newsdata),
                                                                    'appdetail':appdetail,
                                                                    'last':alpdata,
                                                                    'u':request.session.get('email'),'smart_contract':smart_contract})
            except:
                return render(request,'userpages/transactions.html',{'userid':id,
                                                                     'ref_link':ref_link,
                                                                     'newsdata':newsdata,
                                                                        'size':len(newsdata),
                                                                        'appdetail':appdetail,
                                                                        'last':alpdata,
                                                                        'u':request.session.get('email'),
                                                                        'smart_contract':smart_contract})

def income(request):
    if request.session.has_key('email')  and request.session.get('role') == 'user'  and request.session.has_key('token'):  
        try:
            d = jwt.decode(request.session.get('token'), key=KEYS, algorithms=['HS256'])
            if d.get('email')!=request.session.get('email'):
                return redirect('../../../')
        except:
            try:
                del request.session['email']
                del request.session['role']
                del request.session['token']
            except:
                pass
            return redirect('../../../')
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        try:
            alpdata=getdata().get('data').get('last')
        except:
            alpdata=None
        smart_contract=WithdrawSettingModel.objects.get(id=1)
        usr=User.objects.get(email=request.session.get('email')).id
        if usr.paid_members=='False':
            #return redirect('../../plan')
            pass
        if True:
            user=User.objects.get(email=request.session.get('email'))
            if user.verified_at=='True' and user.status=='1':
                if user.paid_members=='True':
                    ref_link=invite(user.referal_code)    
                else:
                    ref_link=None  
            usr_refferal=UserReferral.objects.filter(parent_id=usr )
            child_id=[i.child_id for i in usr_refferal]
            child_users=User.objects.filter(email__in=child_id)
            usr=User.objects.get(email=request.session.get('email'))
            currnet_date=str(datetime.utcnow())[:10]
    
            newsdata=newsmodel.objects.filter(datato__gt=currnet_date,status='True',date__lte=currnet_date)

            return render(request,'userpages/income.html',{'userdata':usr,'child_users':child_users,
                                                       'ref_link':ref_link,
                                                       'newsdata':newsdata,
                                                        'size':len(newsdata),
                                                        'appdetail':appdetail,
                                                        'last':alpdata,
                                                        'u':request.session.get('email'),
                                                        'smart_contract':smart_contract})
    else:
        return redirect("../../../")

def userprofile(request):
    if request.session.has_key('email')  and request.session.get('role') == 'user'  and request.session.has_key('token'):  
        try:
            d = jwt.decode(request.session.get('token'), key=KEYS, algorithms=['HS256'])
            if d.get('email')!=request.session.get('email'):
                return redirect('../../../')
        except:
            try:
                del request.session['email']
                del request.session['role']
                del request.session['token']
            except:
                pass
            return redirect('../../../')
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        try:
            alpdata=getdata().get('data').get('last')
        except:
            alpdata=None
        User = get_user_model()
        user=User.objects.get(email=request.session.get('email'))
        smart_contract=WithdrawSettingModel.objects.get(id=1)
        if user.verified_at=='True' and user.status=='1':
            if user.paid_members=='True':
                ref_link=invite(user.referal_code)    
            else:
                ref_link=None  
        if request.method == 'POST':
            uname=request.POST.get('fullName')
            
            first_name=uname[:uname.find(' ')]
            last_name = uname[uname.find(' '):]
            usr=User.objects.get(email=request.session.get('email'))
            usr.first_name=first_name
            usr.last_name=last_name
        
            usr.save()

        profiledata=User.objects.get(email=request.session.get('email'))
        usr=User.objects.get(email=request.session.get('email'))
        currnet_date=str(datetime.utcnow())[:10]
    
        newsdata=newsmodel.objects.filter(datato__gt=currnet_date,status='True',date__lte=currnet_date)
        return render(request,'userpages/users-profile.html',{'userdata':usr,'ref_link':ref_link,
                                                              'newsdata':newsdata,
                                                            'size':len(newsdata),'appdetail':appdetail,
                                                            'last':alpdata,
                                                            'u':request.session.get('email'),
                                                            'smart_contract':smart_contract})
    else:
        return redirect('../../../')

def signout(request):
    if request.session.has_key('email')  and request.session.get('role') == 'user'  and request.session.has_key('token'):  
        try:
            d = jwt.decode(request.session.get('token'), key=KEYS, algorithms=['HS256'])
            if d.get('email')!=request.session.get('email'):
                return redirect('../../../')
        except:
            try:
                del request.session['email']
                del request.session['role']
                del request.session['token']
            except:
                pass
            return redirect('../../../')
        usr= User.objects.get(email=request.session.get('email'))
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        
        data=list(Login_history.objects.filter(user_id=usr.id))
        if len(data)>0:
            data=max([i.id for i in data])
            data=Login_history.objects.get(id=data)
            data.logout_time=datetime.utcnow()
            data.save()
        del request.session['email']
        del request.session['role']
        try:
            del request.session['token']
        except:
            pass
        response=redirect('../../../')

        return response
    else:
        return redirect('../../../')
    

    
def plancontent(request):
    if request.session.has_key('email')  and request.session.get('role') == 'user'  and request.session.has_key('token'):  
        try:
            d = jwt.decode(request.session.get('token'), key=KEYS, algorithms=['HS256'])
            if d.get('email')!=request.session.get('email'):
                return redirect('../../../')
        except:
            try:
                del request.session['email']
                del request.session['role']
                del request.session['token']
            except:
                pass
            return redirect('../../../')
        user=User.objects.get(email=request.session.get('email'))
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        try:
            alpdata=getdata().get('data').get('last')
        except:
            alpdata=None
        smart_contract=WithdrawSettingModel.objects.get(id=1)
        if user.verified_at=='True' and user.status=='1':
            if user.paid_members=='True':
                ref_link=invite(user.referal_code)    
            else:
                ref_link=None  
        currnet_date=str(datetime.utcnow())[:10]
    
        newsdata=newsmodel.objects.filter(datato__gt=currnet_date,status='True',date__lte=currnet_date)
        return render(request,'userpages/plancontent.html',{'ref_link':ref_link,'newsdata':newsdata,
                                                            'size':len(newsdata),
                                                            'appdetail':appdetail,
                                                            'last':alpdata,
                                                            'u':request.session.get('email'),
                                                            'smart_contract':smart_contract})
    else:
        return render('../../../')





def allplans(request):
    if request.session.has_key('email')  and request.session.get('role') == 'user'  and request.session.has_key('token'):  
        try:
            d = jwt.decode(request.session.get('token'), key=KEYS, algorithms=['HS256'])
            if d.get('email')!=request.session.get('email'):
                return redirect('../../../')
        except:
            try:
                del request.session['email']
                del request.session['role']
                del request.session['token']
            except:
                pass
            return redirect('../../../')
        user=User.objects.get(email=request.session.get('email'))
        smart_contract=WithdrawSettingModel.objects.get(id=1)
        
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        try:
            alpdata=getdata().get('data').get('last')
        except:
            alpdata=None
        if user.verified_at=='True' and user.status=='1':
            if user.paid_members=='True':
                ref_link=invite(user.referal_code)    
            else:
                ref_link=None
        
        data=plansmodel.objects.filter(status='1')
         
        currnet_date=str(datetime.utcnow())[:10]
    
        newsdata=newsmodel.objects.filter(datato__gt=currnet_date,status='True',date__lte=currnet_date)
        print(len(newsdata))
        return render(request,'userpages/plans.html',{'data':data,
                                                      'ref_link':ref_link,
                                                      'newsdata':newsdata,
                                                      'last':alpdata,
                                                            'size':len(newsdata),'appdetail':appdetail,
                                                            'u':request.session.get('email'),
                                                            'smart_contract':smart_contract})
    else:
        return render('../../../')

def userdata(request,pk=None):
    if request.session.has_key('email')  and request.session.get('role') == 'user'  and request.session.has_key('token'):  
        try:
            d = jwt.decode(request.session.get('token'), key=KEYS, algorithms=['HS256'])
            if d.get('email')!=request.session.get('email'):
                return redirect('../../../')
        except:
            try:
                del request.session['email']
                del request.session['role']
                del request.session['token']
            except:
                pass
            return redirect('../../../')
        message1=None
        smart_contract=WithdrawSettingModel.objects.get(id=1)
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        try:
            alpdata=getdata().get('data').get('last')
        except:
            alpdata=None
        if request.method=='POST':
            if 'changepassword' in request.POST:
                current_password=request.POST.get('current_password')
                new_password=request.POST.get('new_password')
                confirm_password=request.POST.get('confirm_password')
                usr=authenticate(username=User.objects.get(email=request.session.get('email')).username,password=current_password)
                if usr:
                    if new_password==confirm_password:
                        usr.password=make_password(new_password)
                        usr.save()
                    else:
                        message1='Confirm password and new password does not match'
                else:
                    message1='Incorrect Current password'
            elif 'change' in request.POST:
                first_name=request.POST.get('first_name')
                last_name=request.POST.get('last_name')
                address=request.POST.get('address')
                pincode=request.POST.get('pincode')
                state=request.POST.get('state')
                district=request.POST.get('district')
                country=request.POST.get('country')
                usr=User.objects.get(email=request.session.get('email'))
                usr.first_name=first_name
                usr.last_name=last_name
                usr.save()
                try:
                    addr=UserAddressDetail.objects.get(user_id=usr.id)
                    addr.address=address
                    addr.pincode=pincode
                    addr.state=state
                    addr.country=country
                    addr.district=district
                    addr.save()
                except:
                    UserAddressDetail.objects.create(user_id=usr,address=address,pincode=pincode,state=state,district=district,country=country)

                    

        id=User.objects.get(email=request.session.get('email')).id
        usr=User.objects.get(id=id)
        ref_link=invite(usr.referal_code)    
        if usr.paid_members=='False':
            #return redirect('../../plan')
            pass
        if True:
            try:
                rank=userRank.objects.get(user_id=usr)
                rank_id=rank.id       
                user_rank=Rank.objects.get(id=rank_id)
                rank_points=int(rank.points)
            except:
                user_rank=None
                rank_points=0                  
            try:
                userwallet=wallet.objects.get(user_id=usr)
                transactions=Transactions.objects.filter(wallet_id=userwallet.id)
            except:
                userwallet=None
                transactions=None           
            try:
                userlevel=Current_level.objects.get(user_id=usr)
                level_points=int(userlevel.points)
            except:
                userlevel=None
                level_points=0
            total_points=int(rank_points)+int(level_points)
            usr_refferal=UserReferral.objects.filter(parent_id=usr)
            usr_refferal=referserial(usr_refferal,many=True)
            usr_refferal=[dict(i) for i in usr_refferal.data]
            refferal_code=User.objects.get(email=request.session.get('email')).referal_code
            path = Path("./config.env")
            load_dotenv(dotenv_path=path)
            SITE_URL = os.getenv('SITE_URL')
            url=f'{SITE_URL}/register/'+refferal_code
            data=[
                {'id':i.get('id'),'name':User.objects.get(id=i.get('child_id')).first_name,
                    'level':Current_level.objects.get(user_id=i.get('child_id')).level_id,
                    'points':Current_level.objects.get(user_id=i.get('child_id')).points,
                    'uid':i.get('child_id'),'pid':i.get('parent_id')} for i in usr_refferal
                    ]
            currnet_date=str(datetime.utcnow())[:10]
    
            newsdata=newsmodel.objects.filter(datato__gt=currnet_date,status='True',date__lte=currnet_date)
                 
            usr=User.objects.get(email=request.session.get('email'))
            try:
                useraddress=UserAddressDetail.objects.get(user_id=usr.id)
            except:
                useraddress=None
            return render(request,'userpages/profile.html',{'user':usr,
                                                                'userRank':user_rank,
                                                                'user_wallet':userwallet,
                                                                'transactions':transactions,
                                                                'usr_refferal':data ,
                                                                'userlevel':  userlevel  ,
                                                                'total_points':total_points,
                                                                'userdata':usr,
                                                                'link':url ,
                                                                'last':alpdata,
                                                                'ref_link':ref_link,
                                                                'message1':message1 ,
                                                                'newsdata':newsdata,
                                                            'size':len(newsdata) ,
                                                            'appdetail':appdetail ,
                                                            'u':request.session.get('email') ,
                                                            'useraddress':useraddress ,
                                                            'smart_contract':smart_contract                                                         
                                                                })
    else:
        return redirect('../../../')

def get_reffer_data(request,pk=None):
    if pk is not None:
        user_data=User.objects.get(id=pk)
        print(user_data.email)
        data=User.objects.filter(referal_by=user_data.referal_code)
        data=UserSerial(data,many=True)
        child_data=[{'data':i,'direct_income':
                     sum([float(j.get('refferal_income')) for j in UserReferral.objects.filter(parent_id=i.get('id'))])} for i in data.data]
        if len(child_data)>0:
            
            return JsonResponse({'data':child_data,'status':1})
        else:
            return JsonResponse({'status':0})
    else:
        return JsonResponse({'status':0})
    

def invite(refferal_code):
    path = Path("./config.env")
    load_dotenv(dotenv_path=path)
    SITE_URL = os.getenv('SITE_URL')
    url=f'{SITE_URL}/register/'+refferal_code
    return url

    

def index(request):
    currnet_date=str(datetime.utcnow())[:10]
    smart_contract=WithdrawSettingModel.objects.get(id=1)
    data=newsmodel.objects.filter(datato__gte=currnet_date,status='True',date__lte=currnet_date)
    try:
        appdetail=appsettings.objects.get(status='1')
    except:
        appdetail=None
    gallerydata=gallaryimages.objects.filter(status='1')
    
    packages=membership.objects.filter(status='1')
    
    if request.session.has_key('email'):
        reg=None
    else:
        reg=1 
    print('reg-->',reg)
    return render(request,'userpages/landing-official.html',{'data':data,'size':len(data),
                                                              'appdetail':appdetail,
                                                              'gallerydata':gallerydata,
                                                              'packages':packages,
                                                              'register':reg,
                                                              'smart_contract':smart_contract})

def support(request):
    if request.session.has_key('email')  and request.session.get('role') == 'user'  and request.session.has_key('token'):  
        try:
            d = jwt.decode(request.session.get('token'), key=KEYS, algorithms=['HS256'])
            if d.get('email')!=request.session.get('email'):
                return redirect('../../../')
        except:
            try:
                del request.session['email']
                del request.session['role']
                del request.session['token']
            except:
                pass
            return redirect('../../../')
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        try:
            alpdata=getdata().get('data').get('last')
        except:
            alpdata=None
        user=User.objects.get(email=request.session.get('email'))
        smart_contract=WithdrawSettingModel.objects.get(id=1)
        if user.verified_at=='True' and user.status=='1':
            if user.paid_members=='True':
                ref_link=invite(user.referal_code)    
            else:
                ref_link=None  
        if request.method=='POST':
            if 'submit' in request.POST:
                title=request.POST.get('subject')
                question=request.POST.get('message')
                user_id=User.objects.get(email=request.session.get('email'))
                TicketModel.objects.create(user_id=user_id,title=title,question=question)
        id=User.objects.get(email=request.session.get('email')).id
        obj=TicketModel.objects.filter(user_id=id)
        currnet_date=str(datetime.utcnow())[:10]
    
        newsdata=newsmodel.objects.filter(datato__gt=currnet_date,status='True',date__lte=currnet_date)
        return render(request,'userpages/support.html',{'id':id,'data':obj,
                                                        'ref_link':ref_link,
                                                        'newsdata':newsdata,
                                                            'size':len(newsdata),
                                                            'appdetail':appdetail,
                                                            'last':alpdata,
                                                            'u':request.session.get('email'),
                                                            'smart_contract':smart_contract})



def user_referal(request,pk=None):
    if request.session.has_key('email')  and request.session.get('role') == 'user'  and request.session.has_key('token'):  
        try:
            d = jwt.decode(request.session.get('token'), key=KEYS, algorithms=['HS256'])
            if d.get('email')!=request.session.get('email'):
                return redirect('../../../')
        except:
            try:
                del request.session['email']
                del request.session['role']
                del request.session['token']
            except:
                pass
            return redirect('../../../')
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        id=User.objects.get(email=request.session.get('email')).id
        smart_contract=WithdrawSettingModel.objects.get(id=1)
        data=None
        try:
            alpdata=getdata().get('data').get('last')
        except:
            alpdata=None
        
        usr=User.objects.get(id=id)

        if usr.paid_members=='False':
            #return redirect('../../plan')
            pass
        ref_link=invite(usr.referal_code)  
        usr=usr.referal_code
        
        currnet_date=str(datetime.utcnow())[:10]
        newsdata=newsmodel.objects.filter(datato__gt=currnet_date,status='True',date__lte=currnet_date)
        
        data=User.objects.filter(referal_by=usr)
        usr_data=[]
        for i in data:
            a={'user':i}
            try:
                u=UserReferral.objects.get(child_id=i.id)
                a['referral_income']=u.refferal_income
            except:
                a['referral_income']=0
            usr_data.append(a)
            

        
        return render(request,'userpages/users.html',{
                                                      'data':usr_data,
                                                      'ref_link':ref_link,
                                                      'newsdata':newsdata,
                                                            'size':len(newsdata),
                                                            'appdetail':appdetail,
                                                            'last':alpdata,
                                                            'u':request.session.get('email'),
                                                            'smart_contract':smart_contract})
        
    else:
         return redirect('../../../')
    



def userpackage(request):
    if request.session.has_key('email')  and request.session.get('role') == 'user'  and request.session.has_key('token'):  
        try:
            d = jwt.decode(request.session.get('token'), key=KEYS, algorithms=['HS256'])
            if d.get('email')!=request.session.get('email'):
                return redirect('../../../')
        except:
            try:
                del request.session['email']
                del request.session['role']
                del request.session['token']
            except:
                pass
            return redirect('../../../')
        try:
            alpdata=getdata().get('data').get('last')
        except:
            alpdata=None
        appdetail=list(appsettings.objects.all())[-1]
        id=User.objects.get(email=request.session.get('email')).id  
        user=User.objects.get(email=request.session.get('email'))
        smart_contract=WithdrawSettingModel.objects.get(id=1)
        if user.verified_at=='True' and user.status=='1':
            if user.paid_members=='True':
                ref_link=invite(user.referal_code)    
            else:
                ref_link=None        
        obj=UserMembership.objects.filter(user_id=id)
        data=[
            {"plan_name":plansmodel.objects.get(id=membership.objects.get(id=i.plan_id.id).plan_id.id).name,'name':membership.objects.get(id=i.plan_id.id).name,
                  'amount':i.amount,'refferal_commision':membership.objects.get(id=i.plan_id.id).refferal_commision,
                  'date':i.date} for i in obj
                  ]
        currnet_date=str(datetime.utcnow())[:10]
    
        newsdata=newsmodel.objects.filter(datato__gt=currnet_date,status='True',date__lte=currnet_date)
        return render(request,'userpages/userpackage.html',{'data':data,'ref_link':ref_link,
                                                            'newsdata':newsdata,
                                                            'size':len(newsdata),
                                                            'appdetail':appdetail,
                                                            'last':alpdata,
                                                            'u':request.session.get('email'),
                                                            'smart_contract':smart_contract})   
    else:
         return redirect('../../../')



def resend_otp(request,pk=None):
    if request.session.has_key('email')  and request.session.get('role') == 'user'  and request.session.has_key('token'):  
        try:
            d = jwt.decode(request.session.get('token'), key=KEYS, algorithms=['HS256'])
            if d.get('email')!=request.session.get('email'):
                return redirect('../../../')
        except:
            try:
                del request.session['email']
                del request.session['role']
                del request.session['token']
            except:
                pass
            return redirect('../../../')
        if pk is None:
            return redirect('../../../')
        appdetail=list(appsettings.objects.all())[-1]
        email=request.session.get('email')
        user=User.objects.get(email=email)
        otp = ''.join([str(rd(0, 9)) for i in range(4)])
        user.created_at=int(time.time())
        user.remember_token=otp
        user.save()
        smart_contract=WithdrawSettingModel.objects.get(id=1)
        emailsettings=Emailservice.objects.get(status='1')
        send_otp(email,otp,emailsettings)
        return render(request,'userpages/otp_2.html',{'message3':'OTP sent to your email address','email':email,'appdetail':appdetail,'type':pk,
                                                      'smart_contract':smart_contract})
    else:
        return redirect('../../../')
    



def resetpass(request):
    if request.session.has_key('email')  and request.session.get('role') == 'user'  and request.session.has_key('token'):  
        try:
            d = jwt.decode(request.session.get('token'), key=KEYS, algorithms=['HS256'])
            if d.get('email')!=request.session.get('email'):
                return redirect('../../../')
        except:
            try:
                del request.session['email']
                del request.session['role']
                del request.session['token']
            except:
                pass
            return redirect('../../../')
        appdetail=list(appsettings.objects.all())[-1]
        if request.method=='POST':
            message=None
            password=request.POST.get('password')
            confirmpassword=request.POST.get('confirmpassword')
            email=request.POST.get('email')
            if password==confirmpassword:
                password=make_password(password)
                user=User.objects.get(email=email)
                user.password=password
                user.save()
                del request.session['reset']
                request.session['email']=email
                request.session['role']=user.role
                if user.role=='user':
                    return redirect('../../../dashboard')
                elif user.role=='admin':
                    return redirect('../../../admin/dashboard')
            else:
                message='Password and Confirm Password Mismatch'
                return render(request,'userpages/resetpassword.html',{'message':message,'appdetail':appdetail,'email':email})
        else:
            return redirect('../../../')
        






def buyplan(request):
    if request.session.has_key('email')  and request.session.get('role') == 'user'  and request.session.has_key('token'):  
        try:
            d = jwt.decode(request.session.get('token'), key=KEYS, algorithms=['HS256'])
            if d.get('email')!=request.session.get('email'):
                return redirect('../../../')
        except:
            try:
                del request.session['email']
                del request.session['role']
                del request.session['token']
            except:
                pass
            return redirect('../../../')
        message=None
        message1=None
        smart_contract=WithdrawSettingModel.objects.get(id=1)
        try:
            alpdata=getdata().get('data').get('last')
        except:
            alpdata=None
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        user_id=User.objects.get(email=request.session.get('email')).id
        usr=User.objects.get(id=user_id)
        ref_link=invite(usr.referal_code) 
        currnet_date=str(datetime.utcnow())[:10]
        if 'buyplan' in request.POST:   
            id=request.POST.get('id')
            amount=request.POST.get('amount')
            memberplan=membership.objects.get(id=id)
            min_amount=memberplan.min_amount
            max_amount=memberplan.max_amount
            obj=membership.objects.filter(status='1')
            newsdata=newsmodel.objects.filter(datato__gt=currnet_date,status='True',date__lte=currnet_date)
            u_wallet=wallet.objects.get(user_id=user_id)
            if float(amount)%50 !=0 or float(amount)<float(min_amount) or float(amount)>float(max_amount):
                message1='selected amount is incorrect'
                return render(request,'userpages/membership.html',{'data':obj,'message1':message1,
                                                               'ref_link':ref_link,'appdetail':appdetail,
                                                               'u':request.session.get('email'),
                                                               'newsdata':newsdata,
                                                               'last':alpdata,
                                                               'size':len(newsdata),
                                                               'smart_contract':smart_contract,
                                                               })

            if float(amount)>float(u_wallet.avaliable_balance):
                message1='Insufficient Balance'
                return render(request,'userpages/membership.html',{'data':obj,'message1':message1,
                                                               'ref_link':ref_link,'appdetail':appdetail,
                                                               'u':request.session.get('email'),
                                                              'newsdata':newsdata,
                                                               'size':len(newsdata),
                                                               'smart_contract':smart_contract
                                                               })
                
            
                
            user_id=User.objects.get(email=request.session.get('email'))
            


            already=sum([float(i.amount) for i in UserMembership.objects.filter(user_id=user_id.id)])
            if float(already)>float(amount):
                message1='SELECTED PLAN IS UNABALIABLE FOR YOU'
                print(message1)
                return render(request,'userpages/membership.html',{'data':obj,'message1':message1,
                                                               'ref_link':ref_link,'appdetail':appdetail,
                                                               'u':request.session.get('email'),
                                                              'newsdata':newsdata,
                                                         'smart_contract':smart_contract,
                                                               'size':len(newsdata),
                                                               'message1':message1,
                                                               }) 
           

            #creating user membership
            next_date= datetime.utcnow() + timedelta(days=1)
            UserMembership.objects.create(user_id=user_id,plan_id=membership.objects.get(id=id),amount=amount,max_roi=membership.objects.get(id=id).overall_roi,status='1',next_date=next_date) 
            u_wallet.avaliable_balance=float(u_wallet.avaliable_balance)-float(amount)
            u_wallet.save()
            user_id.paid_members='True'
            user_id.activation_date= str(time.time())     
            user_id.save()

            while True:
                if user_id.referal_by is not None:
                    try:
                        parent=User.objects.get(referal_code=user_id.referal_by)
                    except:
                        break
                    if parent.verified_at=='True'  : 
                        parent.business=float(parent.business)+float(amount)
                        parent.save()
                        businesslogs.objects.create(parent_id=parent,child_id=user_id,plan_id=membership.objects.get(id=id),amount=amount)
                        # cofounder_data=list(set([int(i.user_id.id) for i in usercofounderclub.objects.all()]))
                        # if len(cofounder_data)<500 and len(UserReferral.objects.filter(parent_id=parent.id))>=3:
                        #     all_cofounder_data=[k for k in cofounderclub.objects.filter(status='1').exclude(id__in=[k.club_id for k in usercofounderclub.objects.filter(user_id=parent.id)]) if float(k.business)<=float(parent.business)]
                        #     for m in all_cofounder_data:
                        #         usercofounderclub.objects.create(user_id=parent,club_id=m,reward_recieved=m.reward)
                        # all_ranks=[k for k in Rank.objects.filter(status='1').exclude(id__in=[k.rank_id.id for k in userRank.objects.filter(user_id=parent.id)]) if float(k.business_required)<=float(parent.business)]
                        # for m in all_ranks:
                        #     userRank.objects.create(user_id=parent,rank_id=m,reward_recieved=m.reward,income=m.royality_income)

                        
                        user_id=User.objects.get(id=parent.id)
                        

                    else:
                        break
                else:
                    break
            #userlevel
            user_id=User.objects.get(email=request.session.get('email'))
            try:
                user_level=userunlockedlevel.objects.get(user_id=user_id.id)
            except:
                userunlockedlevel.objects.create(user_id=User.objects.get(email=request.session.get('email')),level_id=levels.objects.get(id=1))

            
            if user_id.referal_by is not None:
                try:
                    parent=User.objects.get(referal_code=user_id.referal_by)
                except:
                    return redirect('../../../package')
              
                if parent.verified_at=='True':

                    try:
                        usr_ref=UserReferral.objects.get(parent_id=parent.id,child_id=user_id.id)
                        message='Package Bought Successfully'
                        return render(request,'userpages/membership.html',{'data':obj,'message':message,
                                                               'ref_link':ref_link,'appdetail':appdetail,
                                                               'u':request.session.get('email'),
                                                           'smart_contract':smart_contract,
                                                               'newsdata':newsdata})
                    except:
                        UserReferral.objects.create(parent_id=parent,child_id=user_id,level_id=levels.objects.get(id='1'),refferal_income=(float(amount)/100)*5)
                        parent_wallet=wallet.objects.get(user_id=parent.id)
                        parent_wallet.avaliable_balance=float(parent_wallet.avaliable_balance)+float(amount)/100*5
                        parent_wallet.referral_balance=float(parent_wallet.referral_balance)+float(amount)/100*5
                        parent_wallet.save()


                        #parent unlocked levels
                        parent_unlocked_levels=userunlockedlevel.objects.get(user_id=parent.id)
                        try:
                            first_lev=levels.objects.get(id=int(parent_unlocked_levels.level_id.id)+1)
                            print(first_lev)
                            parent_unlocked_levels.level_id=first_lev
                            parent_unlocked_levels.save()
                        except:
                            pass

                        try:
                            next_lev=levels.objects.get(i=parent_unlocked_levels+2)
                            parent_unlocked_levels.level_id=next_lev
                            parent_unlocked_levels.save()
                        except:
                            pass
                    message='Package Bought Successfully'
                    return render(request,'userpages/membership.html',{'data':obj,'message':message,
                                                               'ref_link':ref_link,'appdetail':appdetail,
                                                               'u':request.session.get('email'),
                                                               
                                                            'newsdata':newsdata,
                                                            'smart_contract':smart_contract})

                else:
                    message='Package Bought Successfully'
                    return render(request,'userpages/membership.html',{'data':obj,'message':message,
                                                               'ref_link':ref_link,'appdetail':appdetail,
                                                               'u':request.session.get('email'),
                                                          
                                                               'newsdata':newsdata})
            else:
                message='Package Bought Successfully'
                return render(request,'userpages/membership.html',{'data':obj,'message':message,
                                                               'ref_link':ref_link,'appdetail':appdetail,
                                                               'u':request.session.get('email'),
                                                              
                                                               'newsdata':newsdata,
                                                               'smart_contract':smart_contract})      
      

            
        else:
            return redirect('../../../package')
    else:
        return redirect('../../../')





def ptransfer(request):
    if request.session.has_key('email')  and request.session.get('role') == 'user'  and request.session.has_key('token'):  
        try:
            d = jwt.decode(request.session.get('token'), key=KEYS, algorithms=['HS256'])
            if d.get('email')!=request.session.get('email'):
                return redirect('../../../')
        except:
            try:
                del request.session['email']
                del request.session['role']
                del request.session['token']
            except:
                pass
            return redirect('../../../')
        currnet_date=str(datetime.utcnow())[:10]
        smart_contract=WithdrawSettingModel.objects.get(id=1)

        newsdata=newsmodel.objects.filter(datato__gt=currnet_date,status='True',date__lte=currnet_date)

        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        try:
            alpdata=getdata().get('data').get('last')
        except:
            alpdata=None
        message=None
        message1=None
        allusers=User.objects.filter(status='1').exclude(role='admin').exclude(email=request.session.get('email'))
        if request.method=='POST':


            id=request.POST.get('id')
            amount=request.POST.get('amount')
            user_id=User.objects.get(email=request.session.get('email'))
            user_wallet=wallet.objects.get(user_id=user_id.id)
            transfer_user_id=User.objects.get(id=id)
            transfer_wallet=wallet.objects.get(user_id=transfer_user_id.id)
            if float(user_wallet.avaliable_balance)>=float(amount):
                user_wallet.avaliable_balance=float(user_wallet.avaliable_balance)-float(amount)
                user_wallet.save()

                transfer_wallet.avaliable_balance=float(transfer_wallet.avaliable_balance)+float(amount)
                transfer_wallet.save()

                Ptransfer.objects.create(user_id=user_id,child_id=transfer_user_id,wallet_id=user_wallet,amount=amount)
                message='Fund Transferred successfully'
            else:
                message1='Not Sufficient Balance'

        return render(request,'userpages/ptransfer.html',{'u':request.session.get('email'),
                                                      'appdetail':appdetail,
                                                      'newsdata':newsdata,
                                                      'size':len(newsdata),
                                                      'message':message,
                                                      'message1':message1,
                                                      'allusers':allusers,
                                                      'last':alpdata,'smart_contract':smart_contract})
    else:
        return redirect('../../../')
    

def wallettransfer(request):
    if request.session.has_key('email')  and request.session.get('role') == 'user'  and request.session.has_key('token'):  
        try:
            d = jwt.decode(request.session.get('token'), key=KEYS, algorithms=['HS256'])
            if d.get('email')!=request.session.get('email'):
                return redirect('../../../')
        except:
            try:
                del request.session['email']
                del request.session['role']
                del request.session['token']
            except:
                pass
            return redirect('../../../')
        message=None
        message1=None
        smart_contract=WithdrawSettingModel.objects.get(id=1)
        currnet_date=str(datetime.utcnow())[:10]
        try:
            alpdata=getdata().get('data').get('last')
        except:
            alpdata=None

        newsdata=newsmodel.objects.filter(datato__gt=currnet_date,status='True',date__lte=currnet_date)

        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        currnet_date=str(datetime.utcnow())[:10]
        newsdata=newsmodel.objects.filter(datato__gt=currnet_date,status='True',date__lte=currnet_date)
        user_id=User.objects.get(email=request.session.get('email'))
        user_wallet=wallet.objects.get(user_id=user_id.id)
        if request.method=='POST':
            if 'transfer' in request.POST:
                currency=request.POST.get('currency')
                amount=request.POST.get('amount')
                username=request.POST.get('username')
                try:
                    transfer_user_id=User.objects.get(username=username)
                except:
                    message1='Not Sufficient Fund'
                    data=Ptransfer.objects.filter(user_id=user_id.id)
                    return render(request,'userpages/wallettransfer.html',{
                                                      'u':request.session.get('email'),
                                                      'appdetail':appdetail,
                                                      'newsdata':newsdata,
                                                      'size':len(newsdata),
                                                      'message':message,
                                                      'message1':message1,
                                                      'walletdata':user_wallet,
                                                      'data':data,
                                                      'last':alpdata,
                                                      'smart_contract':smart_contract
                                                      })
                transfer_wallet=wallet.objects.get(user_id=transfer_user_id.id)
                if float(user_wallet.avaliable_balance)>=float(amount):
                    user_wallet.avaliable_balance=float(user_wallet.avaliable_balance)-float(amount)
                    user_wallet.save()

                    transfer_wallet.avaliable_balance=float(transfer_wallet.avaliable_balance)+float(amount)
                    transfer_wallet.save()

                    Ptransfer.objects.create(user_id=user_id,child_id=transfer_user_id,wallet_id=user_wallet,amount=amount,currency=currency)
                    message='Fund Transferred successfully'
                else:
                    message1='Not Sufficient Balance'
        data=Ptransfer.objects.filter(user_id=user_id.id)
        return render(request,'userpages/wallettransfer.html',{
                                                      'u':request.session.get('email'),
                                                      'appdetail':appdetail,
                                                      'newsdata':newsdata,
                                                      'size':len(newsdata),
                                                      'message':message,
                                                      'message1':message1,
                                                      'walletdata':user_wallet,
                                                      'data':data,
                                                      'last':alpdata,
                                                      'smart_contract':smart_contract
                                                      })
    else:
        return redirect('../../../')
    



def transferhistory(request):
    if request.session.has_key('email')  and request.session.get('role') == 'user'  and request.session.has_key('token'):  
        try:
            d = jwt.decode(request.session.get('token'), key=KEYS, algorithms=['HS256'])
            if d.get('email')!=request.session.get('email'):
                return redirect('../../../')
        except:
            try:
                del request.session['email']
                del request.session['role']
                del request.session['token']
            except:
                pass
            return redirect('../../../')
        currnet_date=str(datetime.utcnow())[:10]
        smart_contract=WithdrawSettingModel.objects.get(id=1)
        try:
            alpdata=getdata().get('data').get('last')
        except:
            alpdata=None

        newsdata=newsmodel.objects.filter(datato__gt=currnet_date,status='True',date__lte=currnet_date)

        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        message=None
        message1=None
        user_id=User.objects.get(email=request.session.get('email'))
        data=Ptransfer.objects.filter(user_id=user_id.id)
        

        return render(request,'userpages/transferhistory.html',{'u':request.session.get('email'),
                                                      'appdetail':appdetail,
                                                      'newsdata':newsdata,
                                                      'size':len(newsdata),
                                                      'message':message,
                                                      'message1':message1,
                                                      'data':data,
                                                      'last':alpdata,
                                                      'smart_contract':smart_contract
                                                      })
    else:
        return redirect('../../../')
    


def roi_history(request,pk=None):
    if request.session.has_key('email')  and request.session.get('role') == 'user'  and request.session.has_key('token'):  
        try:
            d = jwt.decode(request.session.get('token'), key=KEYS, algorithms=['HS256'])
            if d.get('email')!=request.session.get('email'):
                return redirect('../../../')
        except:
            try:
                del request.session['email']
                del request.session['role']
                del request.session['token']
            except:
                pass
            return redirect('../../../')
        currnet_date=str(datetime.utcnow())[:10]
        smart_contract=WithdrawSettingModel.objects.get(id=1)
        try:
            alpdata=getdata().get('data').get('last')
        except:
            alpdata=None

        newsdata=newsmodel.objects.filter(datato__gt=currnet_date,status='True',date__lte=currnet_date)

        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        message=None
        message1=None
        
        user_id=User.objects.get(email=request.session.get('email'))
           
                
        data=FarmingRoiLogs.objects.filter(user_id=user_id.id)
        return render(request,'userpages/roi_history.html',{'u':request.session.get('email'),
                                                      'appdetail':appdetail,
                                                      'newsdata':newsdata,
                                                      'size':len(newsdata),
                                                      'message':message,
                                                      'message1':message1,
                                                      'data':data,
                                                      'last':alpdata,
                                                      'smart_contract':smart_contract
                                                      
                                                      })
          

        
        


    else:
        return redirect('../../../')
    



def level_income(request):
    if request.session.has_key('email')  and request.session.get('role') == 'user'  and request.session.has_key('token'):  
        try:
            d = jwt.decode(request.session.get('token'), key=KEYS, algorithms=['HS256'])
            if d.get('email')!=request.session.get('email'):
                return redirect('../../../')
        except:
            try:
                del request.session['email']
                del request.session['role']
                del request.session['token']
            except:
                pass
            return redirect('../../../')
        currnet_date=str(datetime.utcnow())[:10]
        smart_contract=WithdrawSettingModel.objects.get(id=1)
        try:
            alpdata=getdata().get('data').get('last')
        except:
            alpdata=None

        newsdata=newsmodel.objects.filter(datato__gt=currnet_date,status='True',date__lte=currnet_date)

        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        message=None
        message1=None
        user_id=User.objects.get(email=request.session.get('email'))
        data=levelincome.objects.filter(parent_id=user_id)
        overalllevelincome=sum([float(i.level_income) for i in data])
        return render(request,'userpages/level_income.html',{'u':request.session.get('email'),
                                                      'appdetail':appdetail,
                                                      'newsdata':newsdata,
                                                      'size':len(newsdata),
                                                      'message':message,
                                                      'message1':message1,
                                                      'data':data,
                                                      'overallincome':overalllevelincome,
                                                      'last':alpdata,
                                                      'smart_contract':smart_contract
                                                      })


    else:
        return redirect('../../../')



def about(request):
    appdetail=list(appsettings.objects.all())[-1]
    return render(request,'userpages/about.html',{'appdetail':appdetail})

def current_farming(request):
    if request.session.has_key('email')  and request.session.get('role') == 'user'  and request.session.has_key('token'):  
        try:
            d = jwt.decode(request.session.get('token'), key=KEYS, algorithms=['HS256'])
            if d.get('email')!=request.session.get('email'):
                return redirect('../../../')
        except:
            try:
                del request.session['email']
                del request.session['role']
                del request.session['token']
            except:
                pass
            return redirect('../../../')
        message=None
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        try:
            alpdata=getdata().get('data').get('last')
        except:
            alpdata=None
        id=User.objects.get(email=request.session.get('email')).id
        usr=User.objects.get(id=id)     
        message=None
        ref_link=invite(usr.referal_code)  
        smart_contract=WithdrawSettingModel.objects.get(id=1)
        
        currnet_date=str(datetime.utcnow())[:10]
        data=UserMembership.objects.filter(status='1',user_id=usr.id)
        newsdata=newsmodel.objects.filter(datato__gt=currnet_date,status='True',date__lte=currnet_date)
        return render(request,'userpages/current_plan.html',{'data':data,'message':message,
                                                               'ref_link':ref_link,'appdetail':appdetail,
                                                               'u':request.session.get('email'),
                                                               'plan_name':'Farming Package','newsdata':newsdata,
                                                               'last':alpdata,
                                                               'size':len(newsdata),'smart_contract':smart_contract})
    else:
        return redirect('../../../')

def current_staking(request):
    if request.session.has_key('email')  and request.session.get('role') == 'user'  and request.session.has_key('token'):  
        try:
            d = jwt.decode(request.session.get('token'), key=KEYS, algorithms=['HS256'])
            if d.get('email')!=request.session.get('email'):
                return redirect('../../../')
        except:
            try:
                del request.session['email']
                del request.session['role']
                del request.session['token']
            except:
                pass
            return redirect('../../../')
        message=None
        smart_contract=WithdrawSettingModel.objects.get(id=1)
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        try:
            alpdata=getdata().get('data').get('last')
        except:
            alpdata=None
        id=User.objects.get(email=request.session.get('email')).id
        usr=User.objects.get(id=id)     
        message=None
        ref_link=invite(usr.referal_code)  
      
        currnet_date=str(datetime.utcnow())[:10]
        data=UserStaking.objects.filter(status='1',user_id=usr.id)
        newsdata=newsmodel.objects.filter(datato__gt=currnet_date,status='True',date__lte=currnet_date)
        return render(request,'userpages/current_plan.html',{'data':data,'message':message,
                                                               'ref_link':ref_link,'appdetail':appdetail,
                                                               'u':request.session.get('email'),
                                                               'plan_name':'Staking','newsdata':newsdata,
                                                               'last':alpdata,
                                                               'size':len(newsdata),'smart_contract':smart_contract})
    else:
        return redirect('../../../')

class dailyincome(APIView):
    def get(self,request,format=None):
        message=None
        message1=None
        message2=None
        
        usr_members=UserMembership.objects.filter(status='1')
        for i in usr_members:
            overall_roi=ManageRoi.objects.all()[0]
            if overall_roi.farming_roi=='0':
                message='Farming Roi is Closed'
                break
            if i.user_id.farming_roi_status=='0':
                continue
            max_roi=float(i.amount)/100*float(i.max_roi)
            roi_left=max_roi-float(i.roi_recieved)
            next_date=str(i.next_date)[:10]
            d1=datetime.strptime(next_date, r"%Y-%m-%d")
            d2=datetime.strptime(str(datetime.utcnow())[:10],r"%Y-%m-%d")
            delta=d1-d2
            delta=int(delta.days)
            if delta>0:
                message='Roi Already Givenn'
                print(delta)
                continue
            else:
                delta=abs(delta)+1
            
            i.next_date=datetime.utcnow()+timedelta(days=1)
            i.save()
            if roi_left>0 :
                
                for k in range(delta):
                
                    next_roi=(float(i.amount)/100*float(i.plan_id.roi))
                    if roi_left>=next_roi:
                        i.roi_recieved=float(i.roi_recieved)+next_roi
                        i.save()
                        logdate=d1+timedelta(days=k)
                        FarmingRoiLogs.objects.create(user_id=i.user_id,plan_id=i,roi=next_roi,date=str(logdate))
                        user_wallet=wallet.objects.get(user_id=i.user_id.id)
                        user_wallet.avaliable_balance=float(user_wallet.avaliable_balance)+next_roi
                        user_wallet.roi_balance=float(user_wallet.roi_balance)+next_roi
                        user_wallet.save()
                        message='Farming Roi Saved Successfully'
                        print(message)
                        levelid=max([int(i.id) for i in levels.objects.all()])
                        child_id=i.user_id
                        if overall_roi.level_income=='1':
                            for j in range(1,levelid+1):
                                if child_id.referal_by is not None:
                                
                                    try:
                                        parent=User.objects.get(referal_code=i.referal_by)
                                        if parent.verified_at=='True' and parent.paid_members=='True' and parent.level_income_status=='0':
                                            try:
                                                level_id=levels.objects.get(id=j)
                                                level_roi=next_roi/100*float(level_id.points)
                                                levelincome.objects.create(parent_id=parent,child_id=child_id,level_id=level_id,level_income=level_roi,date=logdate)
                                                parent_wallet=wallet.objects.get(id=parent.id)
                                                parent_wallet.avaliable_balance=float(parent_wallet.avaliable_balance)+float(next_roi)
                                                parent_wallet.level_balance=float(parent_wallet.level_balance)+float(next_roi)
                                                parent_wallet.save()
                                                child_id=parent
                                                message2='Level Income Saved Successfully'
                                            except:
                                                pass
                                    except:
                                        pass
                        else:
                            message1='Level Income Closed'

                                        

                    else:
                        logdate=d1+timedelta(days=k)
                        i.roi_recieved=float(i.roi_recieved)+roi_left
                        i.status='2'
                        i.save()
                        FarmingRoiLogs.objects.create(user_id=i.user_id,plan_id=i,roi=roi_left,date=logdate)
                      
                        user_wallet=wallet.objects.get(user_id=i.user_id.id)
                        user_wallet.avaliable_balance=float(user_wallet.avaliable_balance)+roi_left
                        user_wallet.roi_balance=float(user_wallet.roi_balance)+roi_left
                        user_wallet.save()
                        message='Farming Roi Saved Successfully'
                        levelid=max([int(i.id) for i in levels.objects.all()])
                        child_id=i.user_id
                        if overall_roi.level_income=='1':
                            for j in range(1,levelid+1):
                                if child_id.referal_by is not None:
                                    try:
                                        parent=User.objects.get(referal_code=i.referal_by)
                                        if parent.verified_at=='True' and parent.paid_members=='True' and parent.level_income_status=='0':
                                            try:
                                                level_id=levels.objects.get(id=j)
                                                level_roi=roi_left/100*float(level_id.points)
                                                levelincome.objects.create(parent_id=parent,child_id=child_id,level_id=level_id,level_income=level_roi,date=logdate)
                                                parent_wallet=wallet.objects.get(id=parent.id)
                                                parent_wallet.avaliable_balance=float(parent_wallet.avaliable_balance)+float(roi_left)
                                                parent_wallet.level_balance=float(parent_wallet.level_balance)+float(roi_left)
                                                parent_wallet.save()
                                                child_id=parent
                                                message2='Level Income Saved Successfully'
                                            except:
                                                pass
                                    except:
                                        pass
                            
            else:
                i.status='2'
                i.save()
        

        return Response({'status':True,message:[message,message1,message2]})


def packages(request):
    currnet_date=str(datetime.utcnow())[:10]
    data=newsmodel.objects.filter(datato__gte=currnet_date,status='True',date__lte=currnet_date)
    try:
        appdetail=appsettings.objects.get(status='1')
    except:
        appdetail=None
    gallerydata=gallaryimages.objects.filter(status='1')
    plan_id=plansmodel.objects.get(name='Farming Package')
    staking_id=plansmodel.objects.get(name='Staking')
    farming_package=membership.objects.filter(plan_id=plan_id.id)
    staking_package=membership.objects.filter(plan_id=staking_id.id)
    return render(request,'userpages/packages.html',{'data':data,'size':len(data),
                                                              'appdetail':appdetail,
                                                              'gallerydata':gallerydata,
                                                              'farming_package':farming_package,
                                                              'staking_package':staking_package,
                                                              
                                                              })

def gallery(request):
    currnet_date=str(datetime.utcnow())[:10]
    data=newsmodel.objects.filter(datato__gte=currnet_date,status='True',date__lte=currnet_date)
    try:
        appdetail=appsettings.objects.get(status='1')
    except:
        appdetail=None
    gallerydata=gallaryimages.objects.filter(status='1')
    plan_id=plansmodel.objects.get(name='Farming Package')
    farming_package=membership.objects.filter(plan_id=plan_id.id)
    return render(request,'userpages/gallery.html',{'data':data,'size':len(data),
                                                              'appdetail':appdetail,
                                                              'gallerydata':gallerydata,
                                                              'farming_package':farming_package,
                                                              }) 



def rankreward(request):
    if request.session.has_key('email')  and request.session.get('role') == 'user'  and request.session.has_key('token'):  
        try:
            d = jwt.decode(request.session.get('token'), key=KEYS, algorithms=['HS256'])
            if d.get('email')!=request.session.get('email'):
                return redirect('../../../')
        except:
            try:
                del request.session['email']
                del request.session['role']
                del request.session['token']
            except:
                pass
            return redirect('../../../')
        message=None
        smart_contract=WithdrawSettingModel.objects.get(id=1)
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        try:
            alpdata=getdata().get('data').get('last')
        except:
            alpdata=None
        id=User.objects.get(email=request.session.get('email')).id
        usr=User.objects.get(id=id)     
        message=None
        ref_link=invite(usr.referal_code)  
        
        currnet_date=str(datetime.utcnow())[:10]
        newsdata=newsmodel.objects.filter(datato__gt=currnet_date,status='True',date__lte=currnet_date)
        userrank=Rank.objects.filter(status='1')
        user_id=User.objects.get(email=request.session.get('email'))
        r=[]
        for i in userrank:
            rank_data={'rank':i}
            try:
                a=userRank.objects.get(user_id=user_id.id,rank_id=i.rank_id.id)
                rank_data['status']=a.status
            except:
                rank_data['status']='0'
            r.append(rank_data)
        print(r)
        return render(request,'userpages/rankandrewards.html',{'message':message,
                                                               'ref_link':ref_link,'appdetail':appdetail,
                                                               'u':request.session.get('email'),
                                                               'plan_name':'Farming Package','newsdata':newsdata,
                                                               'size':len(newsdata),
                                                               'userrank':r,
                                                               'last':alpdata,'smart_contract':smart_contract})
    else:
        return redirect('../../../') 
    
def direct_income(request):
    if request.session.has_key('email')  and request.session.get('role') == 'user'  and request.session.has_key('token'):  
        try:
            d = jwt.decode(request.session.get('token'), key=KEYS, algorithms=['HS256'])
            if d.get('email')!=request.session.get('email'):
                return redirect('../../../')
        except:
            try:
                del request.session['email']
                del request.session['role']
                del request.session['token']
            except:
                pass
            return redirect('../../../')
        message=None
        smart_contract=WithdrawSettingModel.objects.get(id=1)
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        try:
            alpdata=getdata().get('data').get('last')
        except:
            alpdata=None
        id=User.objects.get(email=request.session.get('email')).id
        usr=User.objects.get(id=id)     
        message=None
        ref_link=invite(usr.referal_code)  
      
        currnet_date=str(datetime.utcnow())[:10]
        
        newsdata=newsmodel.objects.filter(datato__gt=currnet_date,status='True',date__lte=currnet_date)
        data=UserReferral.objects.filter(parent_id=usr.id)
        total_income=sum([float(i.refferal_income) for i in data])
        return render(request,'userpages/directincome.html',{'message':message,'total_income':total_income,
                                                               'ref_link':ref_link,'appdetail':appdetail,
                                                               'u':request.session.get('email'),'size':len(newsdata),'data':data,'last':alpdata,'smart_contract':smart_contract})
    else:
        return redirect('../../../')

def depostihistory(request):
    if request.session.has_key('email')  and request.session.get('role') == 'user'  and request.session.has_key('token'):  
        try:
            d = jwt.decode(request.session.get('token'), key=KEYS, algorithms=['HS256'])
            if d.get('email')!=request.session.get('email'):
                return redirect('../../../')
        except:
            try:
                del request.session['email']
                del request.session['role']
                del request.session['token']
            except:
                pass
            return redirect('../../../')
        message=None
        smart_contract=WithdrawSettingModel.objects.get(id=1)
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        try:
            alpdata=getdata().get('data').get('last')
        except:
            alpdata=None
        id=User.objects.get(email=request.session.get('email')).id
        usr=User.objects.get(id=id)     
        message=None
        ref_link=invite(usr.referal_code)  
      
        currnet_date=str(datetime.utcnow())[:10]
        
        newsdata=newsmodel.objects.filter(datato__gt=currnet_date,status='True',date__lte=currnet_date)
        userwallet=wallet.objects.get(user_id=id)
        incomedata=userWithdrawls.objects.filter(wallet_id=userwallet.id,type='1')
        return render(request,'userpages/deposithistory.html',{'message':message,
                                                               'ref_link':ref_link,'appdetail':appdetail,
                                                               'u':request.session.get('email'),'size':len(newsdata),'newsdata':newsdata,
                                                               'data':incomedata,
                                                               'last':alpdata,'smart_contract':smart_contract})
    else:
        return redirect('../../../')
    
def withdrawalihistory(request):
    if request.session.has_key('email')  and request.session.get('role') == 'user'  and request.session.has_key('token'):  
        try:
            d = jwt.decode(request.session.get('token'), key=KEYS, algorithms=['HS256'])
            if d.get('email')!=request.session.get('email'):
                return redirect('../../../')
        except:
            try:
                del request.session['email']
                del request.session['role']
                del request.session['token']
            except:
                pass
            return redirect('../../../')
        message=None
        smart_contract=WithdrawSettingModel.objects.get(id=1)
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        try:
            alpdata=getdata().get('data').get('last')
        except:
            alpdata=None
        id=User.objects.get(email=request.session.get('email')).id
        usr=User.objects.get(id=id)     
        message=None
        ref_link=invite(usr.referal_code)  
      
        currnet_date=str(datetime.utcnow())[:10]
        userwallet=wallet.objects.get(user_id=id)
        newsdata=newsmodel.objects.filter(datato__gt=currnet_date,status='True',date__lte=currnet_date)
        outcomedata=userWithdrawls.objects.filter(wallet_id=userwallet.id,type='0')
        return render(request,'userpages/withdrawhistory.html',{'message':message,
                                                             'data':outcomedata,
                                                             'newsdata':newsdata,
                                                               'ref_link':ref_link,'appdetail':appdetail,
                                                               'u':request.session.get('email'),'size':len(newsdata),
                                                               'last':alpdata,'smart_contract':smart_contract})
    else:
        return redirect('../../../')
    

def topuphistory(request):
    if request.session.has_key('email')  and request.session.get('role') == 'user'  and request.session.has_key('token'):  
        try:
            d = jwt.decode(request.session.get('token'), key=KEYS, algorithms=['HS256'])
            if d.get('email')!=request.session.get('email'):
                return redirect('../../../')
        except:
            try:
                del request.session['email']
                del request.session['role']
                del request.session['token']
            except:
                pass
            return redirect('../../../')
        message=None
        smart_contract=WithdrawSettingModel.objects.get(id=1)
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        try:
            alpdata=getdata().get('data').get('last')
        except:
            alpdata=None
        id=User.objects.get(email=request.session.get('email')).id
        usr=User.objects.get(id=id)     
        message=None
        ref_link=invite(usr.referal_code)  
      
        currnet_date=str(datetime.utcnow())[:10]
        
        newsdata=newsmodel.objects.filter(datato__gt=currnet_date,status='True',date__lte=currnet_date)
        data=Transactions.objects.filter(user_id=usr.id)
        return render(request,'userpages/topuphistory.html',{'message':message,
                                                             'data':data,
                                                             'newsdata':newsdata,
                                                               'ref_link':ref_link,'appdetail':appdetail,
                                                               'u':request.session.get('email'),'size':len(newsdata),
                                                               'last':alpdata,'smart_contract':smart_contract})
    else:
        return redirect('../../../')
    



def tree(request):
    if request.session.has_key('email')  and request.session.get('role') == 'user'  and request.session.has_key('token'):  
        try:
            d = jwt.decode(request.session.get('token'), key=KEYS, algorithms=['HS256'])
            if d.get('email')!=request.session.get('email'):
                return redirect('../../../')
        except:
            try:
                del request.session['email']
                del request.session['role']
                del request.session['token']
            except:
                pass
            return redirect('../../../')
        message=None
        smart_contract=WithdrawSettingModel.objects.get(id=1)
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        try:
            alpdata=getdata().get('data').get('last')
        except:
            alpdata=None
        id=User.objects.get(email=request.session.get('email')).id
        usr=User.objects.get(id=id)
        usr_ref_income=   sum([float(i.refferal_income) for i in UserReferral.objects.filter(parent_id=usr.id)])  
        message=None
        ref_link=invite(usr.referal_code)  
      
        currnet_date=str(datetime.utcnow())[:10]
        
        newsdata=newsmodel.objects.filter(datato__gt=currnet_date,status='True',date__lte=currnet_date)
        data=User.objects.filter(referal_by=usr.referal_code)
        child_data=[{'data':i,'direct_income':
                     sum([float(j.refferal_income) for j in UserReferral.objects.filter(parent_id=i.id)])} for i in data]
        print(child_data)        
        return render(request,'userpages/tree.html',{'message':message,
                                                             'data':child_data,
                                                             'user':usr,
                                                             'newsdata':newsdata,
                                                               'ref_link':ref_link,'appdetail':appdetail,
                                                               'u':request.session.get('email'),'size':len(newsdata),
                                                               'last':alpdata,'smart_contract':smart_contract,
                                                               'usr_ref_income':usr_ref_income})
    else:
        return redirect('../../../')
    
def downlineteam(request):
    if request.session.has_key('email')  and request.session.get('role') == 'user'  and request.session.has_key('token'):  
        try:
            d = jwt.decode(request.session.get('token'), key=KEYS, algorithms=['HS256'])
            if d.get('email')!=request.session.get('email'):
                return redirect('../../../')
        except:
            try:
                del request.session['email']
                del request.session['role']
                del request.session['token']
            except:
                pass
            return redirect('../../../')
        message=None
        data=None
        smart_contract=WithdrawSettingModel.objects.get(id=1)
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        try:
            alpdata=getdata().get('data').get('last')
        except:
            alpdata=None
        id=User.objects.get(email=request.session.get('email')).id
        usr=User.objects.get(id=id)
        
        message=None
        ref_link=invite(usr.referal_code)  
      
        currnet_date=str(datetime.utcnow())[:10]
        
        newsdata=newsmodel.objects.filter(datato__gt=currnet_date,status='True',date__lte=currnet_date)
        if request.method=='POST':
            uname=request.POST.get('username')
            try:
                
                child_id=User.objects.get(username=uname)
                level_id=max([int(i.id) for i in levels.objects.all()])
                usr_referrs=[int(i.id) for i in User.objects.filter(referal_by=usr.referal_code)]
                for i in range(1,level_id-1):
                    if child_id.id in usr_referrs:
                        data=User.objects.filter(referal_by=child_id.referal_code)
                        data=[{'data':i,'direct_income':
                     sum([float(j.refferal_income) for j in UserReferral.objects.filter(parent_id=i.id)])} for i in data]
                        break
                    elif len(usr_referrs)==0:
                        break
                    else:
                        usr_referrs=[i.id for i in User.objects.filter(referal_by__in=usr_referrs)]
                    
                    

            except:
                pass
            try:
                
                child_id=User.objects.get(email=uname)
                print(child_id)
                print(usr)
                level_id=max([int(i.id) for i in levels.objects.all()])
                usr_referrs=[int(i.id) for i in User.objects.filter(referal_by=usr.referal_code)]
                for i in range(1,level_id-1):
                    if child_id.id in usr_referrs:
                        print("hello")
                        data=User.objects.filter(referal_by=child_id.referal_code)
                        data=[{'data':i,'direct_income':
                     sum([float(j.refferal_income) for j in UserReferral.objects.filter(parent_id=i.id)])} for i in data]
                        break
                    else:
                        usr_referrs=[i.id for i in User.objects.filter(referal_by__in=usr_referrs)]
                    

            except:
                pass
               
        return render(request,'userpages/downlineteam.html',{'message':message,
                                                             'user':usr,
                                                             'data':data,
                                                             'newsdata':newsdata,
                                                               'ref_link':ref_link,'appdetail':appdetail,
                                                               'u':request.session.get('email'),'size':len(newsdata),
                                                               'last':alpdata,'smart_contract':smart_contract
                                                               })
    else:
        return redirect('../../../')
