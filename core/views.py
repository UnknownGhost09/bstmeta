from django.shortcuts import render,redirect
from django.contrib.auth.hashers import make_password
from django.contrib.auth import get_user_model
User=get_user_model()
from django.contrib.auth import authenticate
from .models import levels,Rank,userRank,wallet,Transactions,UserReferral,Current_level,Login_history,status_activity,Emailservice,membership,UserMembership,userWithdrawls,WithdrawSettingModel,TicketModel,plansmodel,newsmodel,appsettings,levelincome,UserAddressDetail,UserStaking,gallaryimages,Ptransfer,youtubevideo,cofounderclub,usercofounderclub,ManageRoi,changesponserlogs,categorymodel
from django.http import JsonResponse
from django.conf import settings
KEYS = getattr(settings, "KEY_", None)
from .serializer import Userserial,referserial
from datetime import datetime,timedelta
import time

from django.core.files.storage import FileSystemStorage
import jwt
from django import template
from django.template.defaultfilters import stringfilter
register = template.Library()



def home(request,pk=None):
    if request.session.has_key('email')  and request.session.get('role') == 'admin'  and request.session.has_key('token'):  
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
        u=User.objects.get(email=request.session.get('email'))
        amount=sum([sum([float(i.amount) for i in UserMembership.objects.all()]),sum([float(i.amount) for i in UserStaking.objects.all()])])
        members=[len(UserMembership.objects.all())+len(UserStaking.objects.all())][0]
        usersviamonth=str(datetime.utcnow())[:5]
        lst=[usersviamonth+'0'+str(i) for i in range(1,10)]
        lst.append(usersviamonth+'10')
        lst.append(usersviamonth+'11')
        lst.append(usersviamonth+'12')
        subscription_amount=[sum(i) if len(i)>0 else 0 for i in [[0 if len(i)==0 else float(j.amount) for j in i  ] for i in [UserMembership.objects.filter(date__contains=i) for i in lst]]]
        current_date=str(datetime.utcnow())[:10]
        recent_join=User.objects.filter(status='1',verified_at='True',created_at__contains=current_date).exclude(role='admin')
        recent_withdrawls=userWithdrawls.objects.filter(status='1',date__contains=current_date,type='0')

        recent_deposits=userWithdrawls.objects.filter(status='1',date__contains=current_date,type='1')
        pending_deposit=userWithdrawls.objects.filter(status='0',type='1')
        pending_withdrawls=userWithdrawls.objects.filter(status='0',type='0')
        
        
        data={'total_users':len(User.objects.exclude(role='admin').all()),'total_verified_users':len(User.objects.exclude(role='admin').filter(verified_at='True',paid_members='True')),
              'total_unverified_users':len(User.objects.exclude(role='admin').filter(verified_at='True',paid_members='False')),
              'total_active_users':len(User.objects.exclude(role='admin').filter(status='1',verified_at='True')),
              'total_inactive_users':len(User.objects.exclude(role='admin').filter(status='0')),
              'amount':amount,'withdrawals':sum([float(i.amount) for i in userWithdrawls.objects.filter(status='1',type='0')]),
              
              'subscription_amount':subscription_amount,'u':u,'appdetail':appdetail,
              'recent_join':len(recent_join),'recent_withdrawls_len':sum([float(i.amount) for i in recent_withdrawls]),
              'recent_deposits':recent_deposits,
              "recent_withdrawls":recent_withdrawls,'pending_deposit_len':sum([float(i.amount) for i in pending_deposit]),
              'pending_withdrawls_len':sum([float(i.amount) for i in pending_withdrawls]),"pending_withdrawls":pending_withdrawls,"pending_deposit":pending_deposit,
              'members':members}

        return render(request,'pages/home.html',data)
    else:
        return redirect('../../../')



def rank(request):
    if request.session.has_key('email')  and request.session.get('role') == 'admin'  and request.session.has_key('token'):  
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
        u=User.objects.get(email=request.session.get('email'))
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        if request.method=='POST':
            if 'submit' in request.POST:
                rank=request.POST.get('rank')  
                cash=request.POST.get('cash')
                business_required=request.POST.get('business_required')  
                reward=request.POST.get('reward') 
                days=request.POST.get('days') 
                try:
                    Rank.objects.create(rank=rank,royality_income=cash,business_required=business_required,reward=reward,days=days)
                    message='New Rank Created Successfully'
                except:
                    message1='Rank already Exists'
            elif 'update' in request.POST:
                id=request.POST.get('id')
                rank=request.POST.get('rank')  
                cash=request.POST.get('cash')
                business_required=request.POST.get('business_required')  
                reward=request.POST.get('reward')
                days=request.POST.get('days')

                obj=Rank.objects.get(id=id)
                try:
                    obj.rank=rank
                    obj.royality_income=cash
                    obj.business_required=business_required
                    obj.reward=reward
                    obj.days=days
                    obj.save()
                    message='data updated successfully'
                except:
                    message1='Club With This Name Already Exists'

            else:
                id=request.POST.get('id')
                obj=Rank.objects.get(id=id)
                print(id)
                if obj.status=='1':
                    obj.status='0'
                    message='Rank Deactivated Successfully'
                elif obj.status=='0':
                    obj.status='1'
                    message='Rank Activated Successfully'
                obj.save()
                

        data=Rank.objects.all()
        return render(request,'pages/rank.html',{'u':u,
                                                  'appdetail':appdetail,'rankdata':data,
                                                  'message':message,
                                                  'message1':message1})
    else:
        return redirect('../../../')


def cofounder(request):
    if request.session.has_key('email')  and request.session.get('role') == 'admin'  and request.session.has_key('token'):  
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
        u=User.objects.get(email=request.session.get('email'))
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        if request.method=='POST':
            if 'submit' in request.POST:
                club=request.POST.get('club')
                business=request.POST.get('business')
                reward=request.POST.get('reward')
                try:
                    cofounderclub.objects.create(club=club,business=business,reward=reward)
                    message='Club Created Successfully'
                except:
                    message1='Club Already Exists'
            elif 'update' in request.POST:
                id=request.POST.get('id')
                club=request.POST.get('club')
                business=request.POST.get('business')
                reward=request.POST.get('reward')
                obj=cofounderclub.objects.get(id=id)
                try:
                    obj.club=club
                    obj.business=business
                    obj.reward=reward
                    obj.save()
                    message='Data Updated Successfully'
                except:
                    message1='Club with this name already exists'

            else:
                id=request.POST.get('id')
                obj=cofounderclub.objects.get(id=id)
                print(id)
                if obj.status=='1':
                    obj.status='0'
                    message='Rank Deactivated Successfully'
                elif obj.status=='0':
                    obj.status='1'
                    message='Rank Activated Successfully'
                obj.save()
                

        data=cofounderclub.objects.all()
        return render(request,'pages/cofounderclub.html',{'u':u,
                                                  'appdetail':appdetail,'clubdata':data,
                                                  'message':message,
                                                  'message1':message1})
    else:
        return redirect('../../../')


def userdata(request,pk=None):
    if request.session.has_key('email')  and request.session.get('role') == 'admin'  and request.session.has_key('token'):  
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
        u=User.objects.get(email=request.session.get('email'))
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        if request.method=='POST':
            id=request.POST.get('id')
            print(id)
            usr=User.objects.get(id=id)
            
            if usr.status=='1':          
                usr_wallet=wallet.objects.get(user_id=id)         
                status_activity.objects.create(user_id=User.objects.get(id=id),status='0',amount_freezed=usr_wallet.avaliable_balance)
                usr_wallet.freezed_balance=float(usr_wallet.freezed_balance)+float(usr_wallet.avaliable_balance)
                usr_wallet.avaliable_balance=0
                usr_wallet.save()
                usr.status='0'
                usr.save()
            else:
                status_activity.objects.create(user_id=User.objects.get(id=id),status='1',amount_freezed='0')
                usr.status='1'
                usr.save()
        if pk is not None:
            try:
                
                usr=User.objects.get(id=pk)
                try:
                    rank=userRank.objects.get(user_id=pk)
                    rank_id=rank.id       
                    user_rank=Rank.objects.get(id=rank_id)
                    rank_points=float(rank.points)
                except:
                    user_rank=None
                    rank_points=0                 
                try:
                    userwallet=wallet.objects.get(user_id=pk)

                    transactions=Transactions.objects.filter(wallet_id=userwallet.id)
                except:
                    userwallet=None
                    transactions=None
                
                try:
                    userlevel=Current_level.objects.get(user_id=pk)
                    level_points=float(userlevel.points)
                    
                except:
                    userlevel=None
                    level_points=0

                
                loginhistory=Login_history.objects.filter(user_id=pk)
                if len(loginhistory)==0:
                    loginhistory=None
                                  
                total_points=float(rank_points)+float(level_points)
                usr_refferal=UserReferral.objects.filter(parent_id=pk)
                
                unique_parent_id=[i.child_id for i in usr_refferal]
        


                ref_data=[{'parent_id':i,'level_income':sum([float(i.level_income) for i in levelincome.objects.filter(parent_id=i.id)]),
              
              'direct_ref_income':sum([float(i.refferal_income) for i in UserReferral.objects.filter(parent_id=i.id)]) } for i in unique_parent_id]


                #user refferal Income
                ref_income=sum([float(i.refferal_income) for i in usr_refferal])
                #level Income

                lev=sum([float(i.level_income) for i in levelincome.objects.filter(parent_id=pk)])
                # FastRack Income
             
                
               

                usr_refferal=referserial(usr_refferal,many=True)
                usr_refferal=[dict(i) for i in usr_refferal.data]

        
                statusmodel=status_activity.objects.filter(user_id=pk)
                
                try:
                    user_plan=UserMembership.objects.filter(user_id=pk)
                    plan_data=[membership.objects.get(id=i.plan_id.id) for i in user_plan]
                except:
                    user_plan=None
                    plan_data=None
                incomedata=userWithdrawls.objects.filter(user_id=usr.id,type='1')
                outcomedata=userWithdrawls.objects.filter(user_id=usr.id,type='0')
                print(outcomedata)

                return render(request,'pages/userdata.html',{'user':usr,
                                                             'userRank':user_rank,
                                                             'user_wallet':userwallet,
                                                             'user_transaction':transactions,
                                                             'data':ref_data,
                                                            'userlevel':  userlevel  ,
                                                            'total_points':total_points,
                                                            'login_history':loginhistory,
                                                            'status_activity':statusmodel,
                                                               'u':u  ,
                                                               'user_plan':user_plan,
                                                               'plan_data':plan_data,
                                                               'ref_income':ref_income,
                                                               'lev':lev  ,
                                                               'appdetail':appdetail ,
                                                               'incomedata':incomedata,
                                                               'outcomedata':outcomedata    
                                                             })

            except:
                return redirect('../../../admin/users')
        obj=User.objects.exclude(email=request.session.get('email')).filter(verified_at='True')
      
        return render(request,'pages/users.html',{'userdata':obj,'heading':"All Users",'u':u,'appdetail':appdetail})
    else:
         return redirect('../../../')




def levelsview(request):
    if request.session.has_key('email')  and request.session.get('role') == 'admin'  and request.session.has_key('token'):  
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
        u=User.objects.get(email=request.session.get('email'))
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        if request.method=='POST':
            if 'update' in request.POST:
                id=request.POST.get('id')
                standard=request.POST.get('standard')
                
                obj=levels.objects.get(id=id)
                obj.points=standard
                
                obj.save()
                message='SAVED SUCCESSFULLY'
            if 'create' in request.POST:
                id=request.POST.get('id')
                standard=request.POST.get('standard')
                try:
                    levels.objects.create(id=id,points=standard)
                    message='SAVED SUCCESSFULLY'
                except:
                    message1='ALREADY HAVE THIS LEVEL'
        obj=levels.objects.all()
        
        return render(request,'pages/levels.html',{'levels':obj,
                                                   'u':u,
                                                   'appdetail':appdetail,
                                                   'message':message,
                                                   'message1':message1})
    else:
         return redirect('../../../')
    





# def rank(request):
#     if request.session.has_key('email')  and request.session.get('role') == 'admin'  and request.session.has_key('token'):  

#         u=User.objects.get(email=request.session.get('email'))
#         obj=Rank.objects.all()
#         return render(request,'pages/rank.html',{'ranks':obj,'u':u})
#     else:
#          return redirect('../../../')
    

def userprofile(request):
    if request.session.has_key('email')  and request.session.get('role') == 'admin'  and request.session.has_key('token'):  
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
        message=None
        u=User.objects.get(email=request.session.get('email'))
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        if request.method=='POST':
            if 'changepassword' in request.POST:
                current_password=request.POST.get('current_password')
                new_password=request.POST.get('new_password')
                confirm_password=request.POST.get('confirm_password')
                email=request.session.get('email')
                username=User.objects.get(email=email).username
                usr=authenticate(username=username,password=current_password)
                print(email)
                if usr:
                    
                    if new_password==confirm_password:
                        if current_password==new_password:
                            message1='New Password Can not be same as old Password'
                            usr=User.objects.get(email=request.session.get('email'))
                            try:
                                useraddress=UserAddressDetail.objects.get(user_id=usr.id)
                            except:
                                useraddress=None

                            return render(request,'pages/users-profile.html',{'userdata':usr,'message':message,
                                                          'message1':message1,'u':u,'useraddress':useraddress,
                                                          'appdetail':appdetail})
                        usr.password=make_password(new_password)
                        usr.save()
                        message='Password Changed'
                        del request.session['email']
                        del request.session['role']
                        del request.session['token']
                        return redirect('../../../loginpage')
                    else:
                        message1='Confirm password and new password does not match'
                else:
                    message1='Incorrect Current password'
            if 'change' in request.POST:
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
                    message='SAVED'
                except:
                    UserAddressDetail.objects.create(user_id=usr,address=address,pincode=pincode,state=state,district=district,country=country)
                    message='SAVED'
                    
        usr=User.objects.get(email=request.session.get('email'))
        try:
            useraddress=UserAddressDetail.objects.get(user_id=usr.id)
        except:
            useraddress=None

        return render(request,'pages/users-profile.html',{'userdata':usr,'message':message,
                                                          'message1':message1,'u':u,'useraddress':useraddress,
                                                          'appdetail':appdetail})
    else:
         return redirect('../../../')
    



def signout(request):
    if request.session.has_key('email')  and request.session.has_key('role') and request.session.has_key('token') :
        usr=User.objects.get(email=request.session.get('email'))
        del request.session['email']
        del request.session['role']
        del request.session['token']
        
        data=list(Login_history.objects.filter(user_id=usr.id))
        if len(data)>0:
            data=max([i.id for i in data])
            data=Login_history.objects.get(id=data)
            data.logout_time=datetime.utcnow()
            data.save()
        
        return redirect('../../../')
    else:
        return redirect('../../../')
    

def get_reffer_data(request,pk=None):
    if pk is not None:
    
        usr_refferal=UserReferral.objects.filter(parent_id=pk)
        
        print(usr_refferal)
        if len(usr_refferal)>0:
            
           
            unique_parent_id=[i.child_id for i in usr_refferal]
          
            data=[{'parent_id':Userserial(i).data,'level_income':sum([float(i.level_income) for i in levelincome.objects.filter(parent_id=i.id)]),
              'direct_ref_income':sum([float(i.refferal_income) for i in UserReferral.objects.filter(parent_id=i.id)]) } for i in unique_parent_id]
            
            return JsonResponse({'data':data,'status':1})
        else:
            return JsonResponse({'status':0})
    else:
        return JsonResponse({'status':0})
    

def emailsettings(request,pk=None):
    if request.session.has_key('email')  and request.session.get('role') == 'admin'  and request.session.has_key('token'):  
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
        u=User.objects.get(email=request.session.get('email'))
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        if request.method=='POST':
        
            if 'addservice' in request.POST:
                service=request.POST.get('service')
                host=request.POST.get('host')
                user=request.POST.get('user')
                password=request.POST.get('password')
                port=request.POST.get('port')
                Emailservice.objects.create(service=service,host=host,user=user,password=password,port=port)
            if 'inactive' in request.POST:
                id=request.POST.get('id')
                obj=Emailservice.objects.get(id=id)
                obj.status='1'
                obj.save()
                all_val=Emailservice.objects.exclude(id=id).all()
                for i in all_val:
                    i.status='0'
                    i.save()
            if 'editservice' in request.POST:
                id=request.POST.get('id')
            
                service=request.POST.get('service')
                print(id,service)
                host=request.POST.get('host')
                user=request.POST.get('user')
                password=request.POST.get('password')
                port=request.POST.get('port')
                obj=Emailservice.objects.get(id=id)
                obj.service=service
                obj.host=host
                obj.user=user
                obj.password=password
                obj.port=port
                obj.save()

    
        obj=Emailservice.objects.all()
        return render(request,'pages/email.html',{'emailsettings':obj,'u':u,'appdetail':appdetail})
    else:
        return redirect('../../../')

def verified_users(request):
    if request.session.has_key('email')  and request.session.get('role') == 'admin'  and request.session.has_key('token'):  
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
        u=User.objects.get(email=request.session.get('email'))
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        obj=User.objects.exclude(email=request.session.get('email')).filter(verified_at='True',paid_members='True')
        return render(request,'pages/users.html',{'userdata':obj,'heading':'Verified Users','appdetail':appdetail})
    else:
        return redirect('../../../')


def unpaid_users(request):
    if request.session.has_key('email')  and request.session.get('role') == 'admin'  and request.session.has_key('token'):  
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
        u=User.objects.get(email=request.session.get('email'))
        obj=User.objects.exclude(email=request.session.get('email')).filter(verified_at='True',paid_members='False')
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        return render(request,'pages/users.html',{'userdata':obj,'heading':'Unverified Users','u':u,'appdetail':appdetail})
    else:
        return redirect('../../../')
    

def active(request):
    if request.session.has_key('email')  and request.session.get('role') == 'admin'  and request.session.has_key('token'):  
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
        u=User.objects.get(email=request.session.get('email'))
        obj=User.objects.exclude(email=request.session.get('email')).filter(verified_at='True',status='1')
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        return render(request,'pages/users.html',{'userdata':obj,'heading':'Active Users','u':u,'appdetail':appdetail})
    else:
        return redirect('../../../')
    

def inactive(request):
    if request.session.has_key('email')  and request.session.get('role') == 'admin'  and request.session.has_key('token'):  
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
        obj=User.objects.exclude(email=request.session.get('email')).filter(verified_at='True',status='0')
        u=User.objects.get(email=request.session.get('email'))
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        return render(request,'pages/users.html',{'userdata':obj,'heading':'Inactive Users','u':u,'appdetail':appdetail})
    else:
        return redirect('../../../')
    

def revenue(request):
    if request.session.has_key('email')  and request.session.get('role') == 'admin'  and request.session.has_key('token'):  
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
        u=User.objects.get(email=request.session.get('email'))
        obj=User.objects.exclude(email=request.session.get('email')).filter(verified_at='True',status='0')
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        return render(request,'pages/users.html',{'userdata':obj,'heading':'Inactive Users','u':u,'appdetail':appdetail})
    else:
        return redirect('../../../login')
    

def allplans(request):
    if request.session.has_key('email')  and request.session.get('role') == 'admin'  and request.session.has_key('token'):  
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
        if request.method=='POST':
            id=request.POST.get('id')
            obj=plansmodel.objects.get(id=id)
            if obj.status=='1':
                obj.status='0'
            elif obj.status=='0':
                obj.status='1'
            obj.save()        
        obj=plansmodel.objects.all()
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        u=User.objects.get(email=request.session.get('email'))
        return render(request,'pages/plans.html',{'data':obj,'u':u,'appdetail':appdetail})
    else:
        return redirect('../../../')
    
def packages(request,pk=None):
    if request.session.has_key('email')  and request.session.get('role') == 'admin'  and request.session.has_key('token'):  
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
        u=User.objects.get(email=request.session.get('email'))


        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None

        if pk is not None:
            
            data=categorymodel.objects.filter(plan_id=pk)
            
            category_name=membership.objects.get(id=pk)
            return render(request,'pages/packagedetail.html',{'data':data,
                                                     'message':message,
                                                     'message1':message1,'u':u,
                                                     'appdetail':appdetail,
                                                     'category_name':category_name.name,
                                                     'plan_id':category_name.id})
        if request.method=='POST':
            
            if 'editpackage' in request.POST:
                id=request.POST.get('id')
                name=request.POST.get('name')
                min=request.POST.get('min')
                max=request.POST.get('max')
                roi=request.POST.get('roi')
                overall=request.POST.get('overall')
                obj=membership.objects.get(id=id)
                obj.name=name
                obj.min_amount=min
                obj.max_amount=max
                obj.roi=roi
                obj.overall_roi=overall
                obj.save()
                message='data updated successfully'
            elif 'close' in request.POST:
                pass
          
            elif 'deletepackage' in request.POST:
                id=request.POST.get('id')
                obj=membership.objects.get(id=id)
                obj.status='0'
                obj.save()
                message='data deleted successfully'

         

            elif 'addpackage' in request.POST:
                
                
                name=request.POST.get('name')
                min=request.POST.get('min')
                max=request.POST.get('max')
                roi=request.POST.get('roi')
                overall=request.POST.get('overall')
                membership.objects.create(name=name,min_amount=min,max_amount=max,roi=roi,overall_roi=overall)
                message='data created successfully'
            elif 'addsubpackage' in request.POST:
                name=request.POST.get('name')
                min_=request.POST.get('min')
                max_=request.POST.get('max')
                plan_id=request.POST.get('plan_id')
                category_name=membership.objects.get(id=plan_id)
                if float(min_)>=float(category_name.min_amount) and float(max_)<=float(category_name.max_amount):
                    categorymodel.objects.create(plan_id=category_name,name=name,min_amount=min_,max_amount=max_)
                    message='Created Successfully'
                else:
                    message1='Mix-Max Criteria is not Correct'
                data=categorymodel.objects.filter(plan_id=plan_id)
            
                
                return render(request,'pages/packagedetail.html',{'data':data,
                                                     'message':message,
                                                     'message1':message1,'u':u,
                                                     'appdetail':appdetail,
                                                     'category_name':category_name.name,
                                                     'message':message,
                                                     'plan_id':category_name.id})
            elif 'deletecategory' in request.POST:
                id=request.POST.get('id')
                obj=membership.objects.get(id=id)
                obj.status='0'
                obj.save()
                message='data deleted successfully'
                plan_id=request.POST.get('plan_id')
                data=categorymodel.objects.filter(plan_id=plan_id)
            
                
                return render(request,'pages/packagedetail.html',{'data':data,
                                                     'message':message,
                                                     'message1':message1,'u':u,
                                                     'appdetail':appdetail,
                                                     'category_name':category_name.name,
                                                     'message':message,
                                                     'plan_id':category_name.id})

            elif 'editcategory' in request.POST:
                name=request.POST.get('name')
                min_=request.POST.get('min')
                max_=request.POST.get('max')
                id=request.POST.get('id')
                plan_id=request.POST.get('plan_id')
                category_name=membership.objects.get(id=plan_id)
                category=categorymodel.objects.get(id=id)
                category.name=name
                print(min_)
                print(category_name.min_amount)
                print(max_)
                print(category_name.max_amount)
                if float(min_)<float(category_name.min_amount):
                    message1='Min Criteria is not correct'
                elif float(max_)>float(category_name.max_amount):
                    message1='Max Criteria is not correct'
                else:
                    category.name=name
                    category.min_amount=min_
                    category.max_amount=max_
                    category.save()
                data=categorymodel.objects.filter(plan_id=plan_id)
            
                
                return render(request,'pages/packagedetail.html',{'data':data,
                                                     'message':message,
                                                     'message1':message1,'u':u,
                                                     'appdetail':appdetail,
                                                     'category_name':category_name.name,
                                                     'message':message,
                                                     'plan_id':category_name.id})

                
            
            
            obj=membership.objects.filter(status='1')
      
            return render(request,'pages/packages.html',{'memberships':obj,
                                                     'message':message,
                                                     'message1':message1,'u':u,
                                                     'appdetail':appdetail})
            
        
            
        u=User.objects.get(email=request.session.get('email'))
            
        obj=membership.objects.filter(status='1')
    
        return render(request,'pages/packages.html',{'memberships':obj,
                                                     'message':message,
                                                     'message1':message1,'u':u,
                                                     'appdetail':appdetail})
        
    else:
        return redirect('../../../')
def referral_users(request):
    if request.session.has_key('email')  and request.session.get('role') == 'admin'  and request.session.has_key('token'):  
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
       
        u=User.objects.get(email=request.session.get('email')) 
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None


        
        data=User.objects.filter(verified_at='True',referal_by=None)
        data=[{'data':i,'direct_income':
                     sum([float(j.refferal_income) for j in UserReferral.objects.filter(parent_id=i.id)])} for i in data]
           
                
        return render(request,'pages/referral_users.html',{'data':data,'u':u,'appdetail':appdetail})
    else:
        return redirect('../../../')
    
def withdraw_manage(request):
    if request.session.has_key('email')  and request.session.get('role') == 'admin'  and request.session.has_key('token'):  
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
        u=User.objects.get(email=request.session.get('email'))
        if request.method=='POST':
            if 'approve' in request.POST:
                id=request.POST.get('id')
                
                obj=userWithdrawls.objects.get(id=id)
                obj.status='1'
                
                obj.save()


            elif 'delete' in request.POST:
                id=request.POST.get('id')
                obj=userWithdrawls.objects.get(id=id)
                obj.status='2'
                usr_id=request.POST.get('user_id')
                user_id=User.objects.get(id=usr_id)
                wallet_id=wallet.objects.get(user_id=user_id.id)
                wallet_id.avaliable_balance=float(obj.amount)+float(wallet_id.avaliable_balance)+float(obj.fees)
                wallet_id.roi_balance=float(wallet_id.roi_balance)+float(obj.roi_amount)
                wallet_id.level_balance=float(wallet_id.level_balance)+float(obj.level_amount)
                wallet_id.bonus_balance=float(wallet_id.bonus_balance)+float(obj.bonus_amount)
                wallet_id.deposit_balance=float(wallet_id.deposit_balance)+float(obj.deposit_amount)
                wallet_id.topup_balance=float(wallet_id.topup_balance)+float(obj.topup_amount)
                wallet_id.reserved_balance=float(wallet_id.reserved_balance)+float(obj.transfer_amount)
                wallet_id.referral_balance=float(wallet_id.referral_balance)+float(obj.direct_amount)
                wallet_id.save()
                
                obj.save()
        obj=userWithdrawls.objects.filter(status='0',type='0')
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
         
        return render(request,'pages/withdraw_manage.html',{'data':obj,'u':u,'appdetail':appdetail})
    else:
        return redirect('../../../')
    
def withdraw_history(request):
    if request.session.has_key('email')  and request.session.get('role') == 'admin'  and request.session.has_key('token'):  
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
        obj=userWithdrawls.objects.filter(type='0')
        u=User.objects.get(email=request.session.get('email'))
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        
        return render(request,'pages/withdraw_history.html',{'data':obj,'u':u,'appdetail':appdetail})
    else:
        return redirect('../../../login')
    

def user_rank(request):
    if request.session.has_key('email')  and request.session.get('role') == 'admin'  and request.session.has_key('token'):  
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
        
        u=User.objects.get(email=request.session.get('email'))
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        data=userRank.objects.all()
        
        return render(request,'pages/userranks.html',{'data':data,'u':u,'appdetail':appdetail})
    else:
        return redirect('../../../login')

def clubhistory(request):
    if request.session.has_key('email')  and request.session.get('role') == 'admin'  and request.session.has_key('token'):  
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
        
        u=User.objects.get(email=request.session.get('email'))
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        data=usercofounderclub.objects.all()
        
        return render(request,'pages/clubhistory.html',{'clubdata':data,'u':u,'appdetail':appdetail})
    else:
        return redirect('../../../login')



def membership_list(request):
    if request.session.has_key('email')  and request.session.get('role') == 'admin'  and request.session.has_key('token'):  
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
    
        user_members=UserMembership.objects.all()

        u=User.objects.get(email=request.session.get('email'))
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
       
       
        return render(request,'pages/membership.html',{'data':user_members,'u':u,'appdetail':appdetail})
    else:
        return redirect('../../../')
    
def staking(request):
    if request.session.has_key('email')  and request.session.get('role') == 'admin'  and request.session.has_key('token'):  
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
    
        user_members=UserStaking.objects.all()

        u=User.objects.get(email=request.session.get('email'))
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
       
       
        return render(request,'pages/staking.html',{'data':user_members,'u':u,'appdetail':appdetail})
    else:
        return redirect('../../../')

def withdraw_settings(request):
    if request.session.has_key('email')  and request.session.get('role') == 'admin'  and request.session.has_key('token'):  
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
        u=User.objects.get(email=request.session.get('email'))
        if request.method=='POST':
            id=request.POST.get('id')
            min_=request.POST.get('min')
            max_=request.POST.get('max')
            fees=request.POST.get('fees')
            dates=request.POST.get('dates') 
            obj=WithdrawSettingModel.objects.get(id=id)
            obj.min_amount=min_
            obj.max_amount=max_
            obj.fees=fees
            obj.dates=dates
            obj.save()
        obj=WithdrawSettingModel.objects.all()
        date=obj[0].dates
        date=date.split(',')
        date=[int(i) for i in date]
        dates=[{'val':'True','date':i} if i in date else {i:'False','date':i}  for i in range(1,32)]
        
        
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None

        return render(request,'pages/withdraw_setting.html',{'data':obj[0],'u':u,'appdetail':appdetail,'dates':dates})
    else:
        return redirect('../../../')
def ticket(request):
    if request.session.has_key('email')  and request.session.get('role') == 'admin'  and request.session.has_key('token'):  
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
        u=User.objects.get(email=request.session.get('email'))
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        if request.method=='POST':
            if 'reply' in request.POST:
                id=request.POST.get('id')
                answer=request.POST.get('answer')
                obj=TicketModel.objects.get(id=id)
                obj.answer=answer
                obj.status='1'
                obj.save()
            elif 'delete' in request.POST:
                id=request.POST.get('id')
                obj=TicketModel.objects.get(id=id)
                obj.status='1'
                obj.save()
        obj=TicketModel.objects.filter(status='0')
        data=[{'id':i.id,
            'email':User.objects.get(id=i.user_id.id),
            'title':i.title,
            'status':i.status,
            'question':i.question
        } for i in obj]

        return render(request,'pages/ticket.html',{'data':data,'u':u,'appdetail':appdetail})
    else:
        return redirect('../../../')


def ticket_history(request):
    if request.session.has_key('email')  and request.session.get('role') == 'admin'  and request.session.has_key('token'):  
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
        u=User.objects.get(email=request.session.get('email'))
        obj=TicketModel.objects.filter(status='1')
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
       
        return render(request,'pages/history.html',{'data':obj,'u':u,'appdetail':appdetail})
    else:
        return redirect('../../../')

def invest_log(request):
    if request.session.has_key('email')  and request.session.get('role') == 'admin'  and request.session.has_key('token'):  
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
        u=User.objects.get(email=request.session.get('email'))
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        
        return render(request,'pages/invest_log.html',{'data':'','u':u,'appdetail':appdetail})
    else:
        return redirect('../../../')

def refferal_log(request):
    if request.session.has_key('email')  and request.session.get('role') == 'admin'  and request.session.has_key('token'):  
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
        u=User.objects.get(email=request.session.get('email'))
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        return render(request,'pages/reffer_logs.html',{'data':'','u':u,'appdetail':appdetail})
    else:
        return redirect('../../../')
    

    
def transaction_log(request):
    if request.session.has_key('email')  and request.session.get('role') == 'admin'  and request.session.has_key('token'):  
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
        u=User.objects.get(email=request.session.get('email'))
        obj=Transactions.objects.all()
        data=[
            {'name':i.user_id.name,'coin':i.coin,
              'network':i.network,'amount':i.amount,'type':i.type,
              'status':i.status,'created_at':i.created_at} for i in obj
              ]
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None

        return render(request,'pages/transaction_history.html',{'data':data,'u':u,'appdetail':appdetail})
    else:
        return redirect('../../../')
    
def login_log(request):
    if request.session.has_key('email')  and request.session.get('role') == 'admin'  and request.session.has_key('token'):  
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
        u=User.objects.get(email=request.session.get('email'))
        obj=Login_history.objects.all()
        data=[{'username':i.user_id,
              'login_time':i.login_time,'logout_time':i.logout_time,'ip_location':i.ip_location,
              'city':i.city,'region':i.region,'country':i.country} for i in obj]
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None

        return render(request,'pages/login_history.html',{'data':data,'u':u,'appdetail':appdetail})
    else:
        return redirect('../../../')
    
def general_settings(request):
    if request.session.has_key('email')  and request.session.get('role') == 'admin'  and request.session.has_key('token'):  
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
        if request.method=='POST':
            if 'submit' in request.POST:
                name=request.POST.get('name')
                lightlogo=request.FILES.get('lightlogo')
                darklogo=request.FILES.get('darklogo')
                favicon=request.FILES.get('favicon')
                fl=FileSystemStorage()
                if appdetail is not None:
                    appdetail.status='0'
                    appdetail.save()

                if lightlogo is None:
                    if appdetail is not None:
                        lightlogo=appdetail.logolight
                    else:
                        lightlogo=None
                else:
                    fl.save(lightlogo.name,lightlogo)
                if darklogo is None:
                    if appdetail is not None:
                        darklogo=appdetail.logodart
                    else:
                        darklogo=None
                else:
                    fl.save(darklogo.name,darklogo)
                if favicon is None:
                    if appdetail is not None:
                        favicon=appdetail.favicon
                    else:
                        favicon=None
                else:
                    fl.save(favicon.name,favicon)
                about=request.POST.get('about')
                fb=request.POST.get('fb')
                insta=request.POST.get('insta')
                twitter=request.POST.get('twitter')
                li=request.POST.get('li') 
                obj=appsettings(title=name,logolight=lightlogo,logodart=darklogo,favicon=favicon,aboutus=about,facebook=fb,twitter=twitter,linkedin=li,instagram=insta)
                obj.save() 
                
        return render(request,'pages/general_settings.html',{'u':request.session.get('email'),'appdetail':appdetail})
    else:
        return redirect('../../../')
    




def eventsview(request):
    if request.session.has_key('email')  and request.session.get('role') == 'admin'  and request.session.has_key('token'):  
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
        if request.method=='POST':
            if 'create' in request.POST:
                eventname=request.POST.get('event')
                date=request.POST.get('date').replace(' ','').split('to')
                if len(date)>1:
                    newsmodel.objects.create(news=eventname,date=date[0],datato=date[1])
                elif len(date)==1:
                    newsmodel.objects.create(news=eventname,date=date[0])
            elif 'update' in request.POST:
                id=request.POST.get('id')
                eventname=request.POST.get('event')
                date=request.POST.get('date').replace(' ','').split('to')
                obj=newsmodel.objects.get(id=id)
                if len(date)>1:
                    obj.news=eventname
                    obj.date=date[0]
                    obj.datato=date[1]
                    obj.save()
                else:
                    obj.news=eventname
                    obj.date=date[0]
                    obj.datato=''
                    obj.save()
                    
            else:
                id=request.POST.get('id')
                obj=newsmodel.objects.get(id=id)
                if obj.status=='True':
                    obj.status='False'
                    obj.save()
                elif obj.status=='False':
                    obj.status='True'
                    obj.save()
                
        currnet_date=str(datetime.utcnow())[:10]
        print(currnet_date)
        data=newsmodel.objects.filter(datato__gt=currnet_date)
        return render(request,'pages/events.html',{'data':data,'u':request.session.get('email'),
                                                   'appdetail':appdetail})
    else:
        return redirect('../../../')
    



def roihistory(request):
    if request.session.has_key('email')  and request.session.get('role') == 'admin'  and request.session.has_key('token'):  
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
        data=UserMembership.objects.all()
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        return render(request,'pages/roihistory.html',{'data':data,'u':request.session.get('email'),'appdetail':appdetail})
    else:
        return redirect('../../../')
    



def stakingroihistory(request):
    if request.session.has_key('email')  and request.session.get('role') == 'admin'  and request.session.has_key('token'):  
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
        data=UserStaking.objects.all()
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        return render(request,'pages/roihistory.html',{'data':data,'u':request.session.get('email'),
                                                       'appdetail':appdetail})
    else:
        return redirect('../../../')
    


def gallery(request):
    if request.session.has_key('email')  and request.session.get('role') == 'admin'  and request.session.has_key('token'):  
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
        if request.method=='POST':
            if 'submit' in request.POST:
                img=request.FILES.get('img')
                title=request.POST.get('title')
                fl=FileSystemStorage()
                fl.save(img.name,img)
                gallaryimages.objects.create(imgpath=img,title=title)
            else:
                id=request.POST.get('id')
                obj=gallaryimages.objects.get(id=id)
                print(obj.status)
                if obj.status=='1':
                    obj.status='0'
                    obj.save()
                elif obj.status=='0':
                    obj.status='1'
                    obj.save()
                
            
        data=gallaryimages.objects.all()
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            
            appdetail=None
        
        return render(request,'pages/gallery.html',{'u':request.session.get('email'),'appdetail':appdetail,'data':data})
    else:
        return redirect('../../../')

def deposite_manage(request):
    if request.session.has_key('email')  and request.session.get('role') == 'admin'  and request.session.has_key('token'):  
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

        if request.method=='POST':
            if 'approve' in request.POST:
                id=request.POST.get('id')
                usr_id=request.POST.get('user_id')
                obj=userWithdrawls.objects.get(id=id)
                user_id=User.objects.get(id=usr_id)
             
                wallet_id=wallet.objects.get(user_id=user_id.id)
                print(wallet_id.id)
                bal=float(wallet_id.avaliable_balance)+float(obj.amount)
                print(bal)
                wallet_id.avaliable_balance=bal
                wallet_id.save()
                obj.status='1'
                obj.save()
            elif 'delete' in request.POST:
                id=request.POST.get('id')
                obj=userWithdrawls.objects.get(id=id)
                obj.status='2'
                obj.save()
        obj=userWithdrawls.objects.filter(type='1',status='0')
        u=User.objects.get(email=request.session.get('email'))
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        
        return render(request,'pages/deposite_manage.html',{'u':u,'appdetail':appdetail,'data':obj})
    else:
        return redirect('../../../')
    

def deposite_history(request):
    if request.session.has_key('email')  and request.session.get('role') == 'admin'  and request.session.has_key('token'):  
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
        obj=userWithdrawls.objects.filter(type='1')
        u=User.objects.get(email=request.session.get('email'))
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        

        return render(request,'pages/deposite_history.html',{'u':u,'appdetail':appdetail,'data':obj})
    else:
        return redirect('../../../')
    
def internal_transfer(request):
    if request.session.has_key('email')  and request.session.get('role') == 'admin'  and request.session.has_key('token'):  
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
        
        u=User.objects.get(email=request.session.get('email'))
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        
        obj=Ptransfer.objects.all()
        return render(request,'pages/internal_transfer.html',{'u':u,'appdetail':appdetail,'data':obj})
    else:
        return redirect('../../../')


def ytvideo(request):
    if request.session.has_key('email')  and request.session.get('role') == 'admin'  and request.session.has_key('token'):  
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
        u=User.objects.get(email=request.session.get('email'))
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        if request.method=='POST':
            if 'addvideo' in request.POST:
                link=request.POST.get('link')
                seq=request.POST.get('seq')
                youtubevideo.objects.create(videolink=link,type='2',sequence=seq)
                message='Video Added Successfully'
            elif 'edit' in request.POST:

                link=request.POST.get('link')
                obj=youtubevideo.objects.filter(type='1',status='1')
                print(link)
                if len(obj)==0:
                    youtubevideo.objects.create(videolink=link)
                    message='Saved Sucessfully'
                else:
                    obj=obj[0]
                    obj.videolink=link
                    obj.save()
                    message='Saved Sucessfully'
                data=obj
            else:
                id=request.POST.get('id')
                obj=youtubevideo.objects.get(id=id)
                if obj.status=='1':
                    obj.status='0'
                    obj.save()
                else:
                    obj.status='1'
                    obj.save()
                print('saved')

            
        data=youtubevideo.objects.filter(status='1',type='1')
        if len(data)>0:
            data=data[0]
        else:
            data=None
        print(data)
        videodata=youtubevideo.objects.filter(type='2')
        return render(request,'pages/ytvideos.html',{'u':u,'appdetail':appdetail,'data':data,'message':message,'message1':message1,'videodata':videodata})
    else:
        return redirect('../../../')
    

def addfund(request,pk=None):
    if request.session.has_key('email')  and request.session.get('role') == 'admin'  and request.session.has_key('token'):  
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
        u=User.objects.get(email=request.session.get('email'))
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        if request.method=='POST':
            if 'freeze' in request.POST:
                id=request.POST.get('id')
                amount=request.POST.get('amount')
                usr_wallet=wallet.objects.get(user_id=id)
                if float(usr_wallet.avaliable_balance)>float(amount):
                    usr_wallet.avaliable_balance=float(usr_wallet.avaliable_balance)-float(amount)
                    usr_wallet.freezed_balance=float(usr_wallet.freezed_balance)+float(amount)
                    usr_wallet.save()
                    Transactions.objects.create(user_id=User.objects.get(id=id),wallet_id=usr_wallet,amount=amount,type='1',status='1',created_at=datetime.utcnow())
                    message='Balance Freezed Successfully'
                    return render(request,'pages/addfund.html',{'u':u,'appdetail':appdetail,'message':message,'message1':message1,'id':pk,'usr_wallet':usr_wallet,'id':id})

            elif 'addfund' in request.POST:
                id=request.POST.get('id')
                amount=request.POST.get('amount')
                usr_wallet=wallet.objects.get(user_id=id)
                usr_wallet.avaliable_balance=float(usr_wallet.avaliable_balance)+float(amount)
                usr_wallet.topup_balance=float(usr_wallet.topup_balance)+float(amount)
                usr_wallet.save()
                Transactions.objects.create(user_id=User.objects.get(id=id),wallet_id=usr_wallet,amount=amount,type='1',status='1',created_at=datetime.utcnow())
                message='Fund Added'

                return render(request,'pages/addfund.html',{'u':u,'appdetail':appdetail,'message':message,'message1':message1,'id':pk,'usr_wallet':usr_wallet,'id':InterruptedError})


        if pk is not None:
            
            usr_wallet=wallet.objects.get(user_id=pk)
        
            return render(request,'pages/addfund.html',{'u':u,'appdetail':appdetail,'message':message,'message1':message1,'id':pk,'usr_wallet':usr_wallet})
        else:
            return redirect('../../admin/dashboard')
    else:
        return redirect('../../../')
    

def admin_login(request,pk=None):
    if request.session.has_key('email')  and request.session.get('role') == 'admin'  and request.session.has_key('token'):  
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

        if pk is not None:
            id=pk
            del request.session['email']
            del request.session['role']
            request.session['email']=User.objects.get(id=id).email
            request.session['role']=User.objects.get(id=id).role
            payload_ = {'email': User.objects.get(id=id).email, 'exp': datetime.utcnow() + timedelta(days=1)}
            usr=User.objects.get(id=id)
            ip=request.META.get('HTTP_X_FORWARDED_FOR')
            if ip:
                ip=ip.split(',')[0]
            else:
                ip=ip = request.META.get('REMOTE_ADDR')
                    
            Login_history.objects.create(user_id=usr,ip_location=ip,login_time=datetime.utcnow())

            token = jwt.encode(payload=payload_,
                                   key=KEYS
                                   ) 
            request.session['token']=token
            return redirect('../../../dashboard')
        else:
            return redirect('../../../admin/dashboard')
    else:
        return redirect('../../../')


def manageuserroi(request):
    if request.session.has_key('email')  and request.session.get('role') == 'admin'  and request.session.has_key('token'):  
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
        u=request.session.get('email')
        message=None
        message1=None
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        if request.method=='POST':
            id=request.POST.get('id')
            name=request.POST.get("name")
            if name=='farming':
                obj=User.objects.get(id=id)
                if obj.farming_roi_status=='1':
                    obj.farming_roi_status='0'
                    obj.save()
                    message='Done'
                else:
                    if obj.zero_pin=='0':
                        obj.farming_roi_status='1'
                        obj.save()
                        message='Done'
                    else:
                        message1='Cannot Change Zero Pin Id'
            elif name=='staking':
                obj=User.objects.get(id=id)
                if obj.staking_roi_status=='1':
                    obj.staking_roi_status='0'
                    obj.save()
                else:
                    obj.staking_roi_status='1'
                    obj.save()
            elif name=='level':
                obj=User.objects.get(id=id)
                if obj.level_income_status=='1':
                    obj.level_income_status='0'
                    obj.save()
                else:
                    obj.level_income_status='1'
                    obj.save()
        else:
            return redirect('../../../../admin/dashboard')
        user_id=User.objects.get(id=id)
                
        return render(request,'pages/manageuserroi.html',{'userdata':user_id,'u':u,'appdetail':appdetail,'message':message,'message1':message1})
                
    else:
        return redirect('../../../')


def manageroi(request,pk=None):
    if request.session.has_key('email')  and request.session.get('role') == 'admin'  and request.session.has_key('token'):  
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
        
        u=User.objects.get(email=request.session.get('email'))
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        if pk is not None:
       
            try:
             
                user_id=User.objects.get(id=pk)
                
                return render(request,'pages/manageuserroi.html',{'userdata':user_id,'u':u,'appdetail':appdetail})
                
            except:
                print("Error")
                return redirect('../../../admin/dashboard')
        if request.method=='POST':
            id=request.POST.get('id')
            name=request.POST.get("name")
            if name=='farming':
                obj=ManageRoi.objects.all()[0]
                if obj.farming_roi=='1':
                    obj.farming_roi='0'
                    obj.save()
                else:
                    
                    obj.farming_roi='1'
                    obj.save()
            elif name=='staking':
                obj=ManageRoi.objects.all()[0]
                if obj.staking_roi=='1':
                    obj.staking_roi='0'
                    obj.save()
                else:
                    obj.staking_roi='1'
                    obj.save()
            elif name=='level':
                obj=ManageRoi.objects.all()[0]
                if obj.level_income=='1':
                    obj.level_income='0'
                    obj.save()
                else:
                    obj.level_income='1'
                    obj.save()
        roi_status=ManageRoi.objects.all()[0]
        

        return render(request,'pages/manage_roi.html',{'u':u,'appdetail':appdetail,'roi_status':roi_status})
        
    else:
        return redirect('../../../')
    

def smart_contract(request):
    if request.session.has_key('email')  and request.session.get('role') == 'admin'  and request.session.has_key('token'):  
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
        u=User.objects.get(email=request.session.get('email'))
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        if request.method=='POST':
            address=request.POST.get('address')
            print(address)
            obj=WithdrawSettingModel.objects.get(id=1)
            obj.bscaddress=address
            obj.save()
            message='Address Saved Successfully'
        
        obj=WithdrawSettingModel.objects.get(id=1)
        print(obj.bscaddress)
        return render(request,'pages/smart_contract.html',{'u':u,'appdetail':appdetail,'data':obj,'message':message})
    else:
        return redirect('../../../')
    

def topup_history(request):
    if request.session.has_key('email')  and request.session.get('role') == 'admin'  and request.session.has_key('token'):  
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
        u=User.objects.get(email=request.session.get('email'))
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        
        
        data=Transactions.objects.all()
        return render(request,'pages/topup_history.html',{'u':u,'appdetail':appdetail,'data':data,'message':message})
    else:
        return redirect('../../../')
    
def change_sponser(request):
    if request.session.has_key('email')  and request.session.get('role') == 'admin'  and request.session.has_key('token'):  
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
        u=User.objects.get(email=request.session.get('email'))
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        if request.method=='POST':
            fromuser=request.POST.get('from')
            touser=request.POST.get('to')
            try:
                fromuser=User.objects.get(username=fromuser)
            except:
                message1='Current Sponser Username not Found'
                return render(request,'pages/change_sponser.html',{'u':u,'appdetail':appdetail,'message1':message1,'message':message})
            try:
                touser=User.objects.get(username=touser)
            except:
                message1='New Sponser Username not Found'
                return render(request,'pages/change_sponser.html',{'u':u,'appdetail':appdetail,'message1':message1,'message':message})
            if touser.status=='0' :
                message1='New Sponser is Not a active User'
                return render(request,'pages/change_sponser.html',{'u':u,'appdetail':appdetail,'message1':message1,'message':message})
            elif fromuser.status=='0':
                message1='Current Sponser is not active user'
                return render(request,'pages/change_sponser.html',{'u':u,'appdetail':appdetail,'message1':message1,'message':message})
            


            usr_ref=[i.id for i in User.objects.filter(referal_by=fromuser.referal_code)]
            a=0
            while True:
                if len(usr_ref)==0:
                    a=1
                    break
                elif touser.id in usr_ref:
                    message1='New Sponser must not be in Downline of Current Sponser'
                    break
                else:
                    usr_ref=[i.id for i in User.objects.filter(referal_by__in=usr_ref)]
            if a==1:
                User.objects.filter(referal_by=fromuser.referal_code).update(referal_code=touser.referal_code)
                UserReferral.objects.filter(parent_id=fromuser.id).update(parent_id=touser)
                changesponserlogs.objects.create(from_id=fromuser,to_id=touser)
                fromuser.status='0'
                fromuser.is_active='0'
                fromuser.farming_roi_status='0'
                fromuser.staking_roi_status='0'
                fromuser.level_income_status='0'
                fromuser.save()
                message='Sponser Changed Successfully'

                


        
        
        
        
        return render(request,'pages/change_sponser.html',{'u':u,'appdetail':appdetail,'message1':message1,'message':message})
    else:
        return redirect('../../../')
    

def level_income(request):
    if request.session.has_key('email')  and request.session.get('role') == 'admin'  and request.session.has_key('token'):  
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
        u=User.objects.get(email=request.session.get('email'))
        try:
            appdetail=appsettings.objects.get(status='1')
        except:
            appdetail=None
        
        
        data=levelincome.objects.all()
        return render(request,'pages/level_income.html',{'u':u,'appdetail':appdetail,'data':data,'message':message})
    else:
        return redirect('../../../')
    

def tree(request,pk=None):
    if request.session.has_key('email')  and request.session.get('role') == 'admin'  and request.session.has_key('token'):  
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
        if pk is not None:
            message=None
            try:
                u=User.objects.get(email=request.session.get('email'))
            except:
                return redirect('../../../admin/dashboard')
            try:
                appdetail=appsettings.objects.get(status='1')
            except:
                appdetail=None
        
            usr=User.objects.get(id=pk)
            usr_ref_income=   sum([float(i.refferal_income) for i in UserReferral.objects.filter(parent_id=usr.id)])  
            message=None
  
            data=User.objects.filter(referal_by=usr.referal_code)
            child_data=[{'data':i,'direct_income':
                     sum([float(j.refferal_income) for j in UserReferral.objects.filter(parent_id=i.id)])} for i in data]
           
    
            return render(request,'pages/tree.html',{'u':u,'appdetail':appdetail,'data':child_data,'usr_ref_income':usr_ref_income,'usr':usr,'message':message})
        else:
            return redirect('../../../admin/dashboard')
    else:
        return redirect('../../../')
    
def unlock_levels(request,pk=None):
    if request.session.has_key('email')  and request.session.get('role') == 'admin'  and request.session.has_key('token'):  
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
        if pk is not None:
            message=None
            message1=None
            try:
                u=User.objects.get(email=request.session.get('email'))
            except:
                return redirect('../../../admin/dashboard')
            try:
                appdetail=appsettings.objects.get(status='1')
            except:
                appdetail=None
            usr=User.objects.get(id=pk)
            usr.zero_pin='1'
            usr.farming_roi_status='0'
            usr.save()
            level_id=max([int(i.id) for i in levels.objects.all()])
            level_id=levels.objects.get(id=level_id)
            try:
                usr_level=Current_level.objects.get(user_id=usr.id)
                usr_level.level_id=level_id
                usr_level.save()
            except:
                Current_level.objects.create(user_id=usr,level_id=level_id)
            message='User Id Changed To Zero Pin ID'
            obj=User.objects.exclude(email=request.session.get('email')).filter(verified_at='True')
            return render(request,'pages/users.html',{'userdata':obj,'u':u,'appdetail':appdetail,'message':message,'message1':message1})
        else:
            return redirect('../../../admin/dashboard')
    else:
        return redirect('../../../')
    
def rank_requests(request):
    if request.session.has_key('email')  and request.session.get('role') == 'admin'  and request.session.has_key('token'):  
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
        u=User.objects.get(email=request.session.get('email'))
        message=None
        message1=None
        if request.method=='POST':
            if 'approve' in request.POST:
                id=request.POST.get('id')
                ob=userRank.objects.get(id=id)
                ob.status='3'
                ob.save()
                message='Done'
            elif 'delete' in request.POST:
               
                id=request.POST.get('id')
                ob=userRank.objects.get(id=id)
                ob.status='4'
                ob.save()
                message='Done'
        data=userRank.objects.filter(status='2')

        return render(request,'pages/claim_rewards.html',{'u':u,'appdetail':appdetail,'message':message,'message1':message1,'data':data})
       
    else:
        return redirect('../../../')