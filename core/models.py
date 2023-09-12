from django.db import models
from django.db import models
from django.db import models
from django.contrib.auth.models import AbstractUser
from datetime import datetime

import uuid
from django.db.models.signals import post_save
from django.dispatch import receiver



class User(AbstractUser):
    email=models.EmailField(unique=True)
    verified_at = models.CharField(max_length=200,default='False')
    role =models.CharField(max_length=200,default='user')
    status = models.CharField(max_length=20, default='1')
    updated_at = models.CharField(max_length=200,default=datetime.utcnow())
    created_at = models.CharField(max_length=200,default=datetime.utcnow())
    remember_token=models.CharField(max_length=200,default='False')
    referal_by=models.CharField(max_length=200,null=True)
    referal_code=models.CharField(max_length=200,unique=True,default='0000')
    phone_no=models.CharField(max_length=200,null=True)
    activation_date=models.CharField(max_length=200,default='N/A')
    paid_members=models.CharField(max_length=200,default='False')
    business=models.CharField(max_length=200,default='0')
    farming_roi_status=models.CharField(max_length=200,default='1')
    staking_roi_status=models.CharField(max_length=100,default='1')
    level_income_status=models.CharField(max_length=100,default='1')
    zero_pin=models.CharField(max_length=200,default='0')
    business_balance=models.CharField(max_length=250,default='0')

    class Meta:
        db_table='users'

class ManageRoi(models.Model):
    farming_roi=models.CharField(max_length=100,default='1')
    staking_roi=models.CharField(max_length=100,default='1')
    level_income=models.CharField(max_length=100,default='1')
    class Meta:
        db_table='manageroi'



class businesslogs(models.Model):
    parent_id=models.ForeignKey("core.User", related_name='%(class)s_parent_id', on_delete=models.CASCADE)
    child_id=models.ForeignKey("core.User",related_name='%(class)s_child_id', on_delete=models.CASCADE)
    amount=models.CharField(max_length=100)
    date=models.CharField(max_length=100,default=datetime.utcnow())
    status=models.CharField(max_length=100,default='1')
    plan_id=models.ForeignKey("core.membership", db_column='plan_id', on_delete=models.CASCADE,default=1)


class UserAddressDetail(models.Model):
    user_id=models.ForeignKey("core.User", db_column='user_id', on_delete=models.CASCADE)
    address=models.CharField(max_length=200)
    pincode=models.CharField(max_length=200)
    district=models.CharField(max_length=200)
    state=models.CharField(max_length=200)
    country=models.CharField(max_length=200,null=True)



class plansmodel(models.Model):
    name=models.CharField(max_length=200,unique=True)
    status=models.CharField(max_length=200)



class changesponserlogs(models.Model):
    from_id=models.ForeignKey("core.User", related_name='%(class)s_from_id', on_delete=models.CASCADE)
    to_id=models.ForeignKey("core.User",related_name='%(class)s_to_id', on_delete=models.CASCADE)
    status=models.CharField(max_length=100,default='1')
    date=models.CharField(max_length=100,default=datetime.utcnow())


class membership(models.Model):
    name=models.CharField(max_length=200)
    points=models.CharField(max_length=200,default=20)
    refferal_commision=models.CharField(max_length=200,default='0')
    directincomepercent=models.CharField(max_length=200,default='50')
    status=models.CharField(max_length=200,default='1')
    roi=models.CharField(max_length=200,default='0')
    roi_period=models.CharField(max_length=200,default='1')
    staking=models.CharField(max_length=100,default=False)
    plan_period=models.CharField(max_length=100,null=True)
    min_amount=models.CharField(max_length=100,default='50')
    max_amount=models.CharField(max_length=100,null=True)
    overall_roi=models.CharField(max_length=200,default='0')
    



class categorymodel(models.Model):
    plan_id=models.ForeignKey("core.membership", db_column='plan_id', on_delete=models.CASCADE)
    name=models.CharField(max_length=250)
    min_amount=models.CharField(max_length=250)
    max_amount=models.CharField(max_length=250)
    status=models.CharField(max_length=100,default='1')


class gallaryimages(models.Model):
    imgpath=models.CharField(max_length=200)
    title=models.TextField(default='The calendar may say spring, but a cool breeze through your open window makes a lightweight throw blanket a must-have.')
    status=models.CharField(max_length=100,default='1')


class UserMembership(models.Model):
    user_id=models.ForeignKey("core.User", db_column='user_id', on_delete=models.CASCADE)
    plan_id=models.ForeignKey("core.membership", db_column='plan_id', on_delete=models.CASCADE)
    c_id=models.ForeignKey("core.categorymodel", db_column='c_id', on_delete=models.CASCADE,default='1')
    amount=models.CharField(max_length=200)
    date=models.CharField(max_length=200,default=datetime.utcnow())
    status=models.CharField(max_length=200,default='0')
    max_roi=models.CharField(max_length=200,default='200')
    booster_plan=models.CharField(max_length=200,default=False)
    roi_recieved=models.CharField(max_length=200,default='0')
    next_date=models.CharField(max_length=200,default='2023-09-01 05:44:45.574389')
    class Meta:
        db_table='usermembership'



class FarmingRoiLogs(models.Model):
    user_id=models.ForeignKey("core.User", db_column='user_id', on_delete=models.CASCADE)
    plan_id=models.ForeignKey("core.UserMembership", db_column='plan_id', on_delete=models.CASCADE)
    date=models.CharField(max_length=200,default=datetime.utcnow())
    status=models.CharField(max_length=100,default='1')
    roi=models.CharField(max_length=200,default='0')

    class Meta:
        db_table='farmingroilogs'








class UserStaking(models.Model):
    user_id=models.ForeignKey("core.User", db_column='user_id', on_delete=models.CASCADE)
    plan_id=models.ForeignKey("core.membership", db_column='plan_id', on_delete=models.CASCADE)
    amount=models.CharField(max_length=200)
    date=models.CharField(max_length=200,default=datetime.utcnow())
    status=models.CharField(max_length=200,default='0')
    roi_per_month=models.CharField(max_length=200,default='3')
    roi_recieved=models.CharField(max_length=200,default='0')
    next_date=models.CharField(max_length=200,default='2023-09-01 05:44:45.574389')
    expire_date=models.CharField(max_length=200,default='2024-09-01 05:44:45.574389')
                               

    

    class Meta:
        db_table='userstaking'


class StakingRoiLogs(models.Model):
    user_id=models.ForeignKey("core.User", db_column='user_id', on_delete=models.CASCADE)
    plan_id=models.ForeignKey("core.membership", db_column='plan_id', on_delete=models.CASCADE)
    roi=models.CharField(max_length=200)
    date=models.CharField(max_length=200,default=datetime.utcnow())
    status=models.CharField(max_length=100,default='1')

    class Meta:
        db_table='stakingroilogs'







class newsmodel(models.Model):
    news=models.CharField(max_length=200)
    date=models.CharField(max_length=100,default=datetime.utcnow())
    status=models.CharField(max_length=200,default=True)
    datato=models.CharField(max_length=200,null=True)




class appsettings(models.Model):
    title=models.CharField(max_length=200)
    logolight=models.CharField(max_length=200)
    logodart=models.CharField(max_length=200)
    favicon=models.CharField(max_length=200)
    aboutus=models.TextField(default='')
    facebook=models.CharField(max_length=200)
    twitter=models.CharField(max_length=200)
    linkedin=models.CharField(max_length=200)
    instagram=models.CharField(max_length=200)
    email=models.CharField(max_length=200)
    status=models.CharField(max_length=200,default='1')


# @receiver(post_save, sender=UserMembership)
# def membership_signal(sender,instance,created,**kwargs):
#     if created:
#         obj=User.objects.get(id=instance.user_id.id)
#         obj.paid_members='True'
#         obj.activation_date=instance.date      
#         obj.save()
#         if obj.referal_by is not None:
#             try:
#                 usr_ref=UserReferral.objects.get(child_id=obj.id)   
#                 print('already reffered')     
#             except:
#                 try:
#                     parent=User.objects.get(referal_code=obj.referal_by)
#                 except:
#                     return 0
#                 if parent.verified_at=='True' and parent.paid_members=='True':
#                     level_id=levels.objects.get(id=1) 
#                     UserReferral.objects.create(parent_id=parent,child_id=obj,level_id=level_id)
#                 else:
#                     print('Not valid refferal code')
        

    

class levels(models.Model):
    points=models.CharField(max_length=200)
    reffers=models.CharField(max_length=250,default='1')
    class Meta:
        db_table='levels'




class userunlockedlevel(models.Model):
    user_id=models.ForeignKey("core.User", db_column='user_id', on_delete=models.CASCADE)
    level_id=models.ForeignKey("core.levels", db_column='level_id', on_delete=models.CASCADE)
    status=models.CharField(max_length=100,default='1')



class Current_level(models.Model):
    user_id=models.ForeignKey("core.User", db_column='user_id', on_delete=models.CASCADE)
    level_id=models.CharField(max_length=200)
    points=models.CharField(max_length=200,default=0)
    class Meta:
        db_table='current_level'



class levelincome(models.Model):
    parent_id=models.ForeignKey("core.User", related_name='%(class)s_parent_id', on_delete=models.CASCADE)
    child_id=models.ForeignKey("core.User",related_name='%(class)s_child_id', on_delete=models.CASCADE)
    level_id=models.ForeignKey("core.levels", db_column='level_id', on_delete=models.CASCADE)
    level_income=models.CharField(max_length=200,default='0')
    date=models.CharField(max_length=100,default=datetime.utcnow())
    status=models.CharField(max_length=100,default='1')


class WithdrawSettingModel(models.Model):
    min_amount=models.CharField(max_length=200)
    max_amount=models.CharField(max_length=200,default=100)
    fees=models.CharField(max_length=200)
    bscaddress=models.CharField(max_length=250,default='0x83F928c66F437507EB399F8E91e84f2fD15C57Ec')
    dates=models.CharField(max_length=250,default='0')


class TicketModel(models.Model):
    user_id=models.ForeignKey("core.User", db_column='user_id', on_delete=models.CASCADE)
    title=models.CharField(max_length=200,default=' No titile')
    question=models.TextField()
    answer=models.TextField(default='')
    status=models.CharField(max_length=200,default='0')
    date=models.CharField(max_length=200,default=datetime.utcnow())



class wallet(models.Model):
    user_id=models.ForeignKey("core.User", db_column='user_id', on_delete=models.CASCADE)
    avaliable_balance=models.CharField(max_length=200,default='0')
    roi_balance=models.CharField(max_length=200,default='0')
    level_balance=models.CharField(max_length=200,default='0')
    bonus_balance=models.CharField(max_length=250,default='0')
    deposit_balance=models.CharField(max_length=250,default='0')
    topup_balance=models.CharField(max_length=250,default='0')
    referral_balance=models.CharField(max_length=200,default='0')
    freezed_balance=models.CharField(max_length=200,default='0')
    reserved_balance=models.CharField(max_length=200,default='0')
    class Meta:
        db_table='wallet'



class userWithdrawls(models.Model):
    user_id=models.ForeignKey("core.User", db_column='user_id', on_delete=models.CASCADE)
    wallet_id=models.ForeignKey("core.wallet", db_column='wallet_id', on_delete=models.CASCADE)
    status=models.CharField(max_length=200,default='0')
    amount=models.CharField(max_length=200)
    currency=models.CharField(max_length=200,default='USDT')
    address=models.CharField(max_length=200,null=True)
    type=models.CharField(max_length=200,default='0')
    date=models.CharField(max_length=200,default=datetime.utcnow())
    fees=models.CharField(max_length=200,default='0')
    roi_amount=models.CharField(max_length=200,default='0')
    level_amount=models.CharField(max_length=250,default='0')
    direct_amount=models.CharField(max_length=250,default='0')
    bonus_amount=models.CharField(max_length=250,default='0')
    transfer_amount=models.CharField(max_length=250,default='0')
    deposit_amount=models.CharField(max_length=250,default='0')
    topup_amount=models.CharField(max_length=250,default='0')



class status_activity(models.Model):
    user_id=models.ForeignKey("core.User", db_column='user_id', on_delete=models.CASCADE)
    time=models.CharField(max_length=200,default=datetime.utcnow())
    status=models.CharField(max_length=100)
    amount_freezed=models.CharField(max_length=200)



class Transactions(models.Model):
    user_id=models.ForeignKey("core.User", db_column='user_id', on_delete=models.CASCADE,default='1')
    wallet_id=models.ForeignKey("core.wallet", db_column='wallet_id', on_delete=models.CASCADE)
    coin=models.CharField(max_length=200,default='n/a')
    network=models.CharField(max_length=200,default='n/a')
    amount=models.CharField(max_length=200,default='n/a')
    address=models.CharField(max_length=200,default='NA')
    type=models.CharField(max_length=200,default='NA')
    status=models.CharField(max_length=200,default='n/a')
    created_at=models.CharField(max_length=200,default='n/a')
    class Meta:
        db_table='transactions'



class Ptransfer(models.Model):
    user_id=models.ForeignKey("core.User", related_name='%(class)s_user_id', on_delete=models.CASCADE)
    child_id=models.ForeignKey("core.User",related_name='%(class)s_child_id', on_delete=models.CASCADE)
    wallet_id=models.ForeignKey("core.wallet", db_column='wallet_id', on_delete=models.CASCADE)
    status=models.CharField(max_length=200,default='1')
    type=models.CharField(max_length=200,default='1')
    date=models.CharField(max_length=200,default=datetime.utcnow())
    amount=models.CharField(max_length=200)
    currency=models.CharField(max_length=200,default='USDT')
    class Meta:
        db_table='ptransfer'
    
    

class UserReferral(models.Model):
    parent_id=models.ForeignKey("core.User", related_name='%(class)s_parent_id', on_delete=models.CASCADE)
    child_id=models.ForeignKey("core.User",related_name='%(class)s_child_id', on_delete=models.CASCADE)
    level_id=models.ForeignKey("core.levels", db_column='level_id', on_delete=models.CASCADE)
    refferal_income=models.CharField(max_length=200,default='0')
    date=models.CharField(max_length=100,default=datetime.utcnow())
    status=models.CharField(max_length=100,default='1')
    class Meta:
        db_table='user_referral'




@receiver(post_save, sender=User)
def create_code(sender,instance,created,**kwargs):
    if created:
        
        uid=uuid.uuid4()
        instance.referal_code=str(uid)[:8]
        instance.save()



@receiver(post_save, sender=User)
def create_referral(sender,instance,created,**kwargs):
    if str(instance.verified_at)=='True':
        try:
            usercurrent_level=Current_level.objects.get(user_id=instance.id)
        except:
            Current_level.objects.create(user_id=instance,level_id=0)
        try:
            userwallet=wallet.objects.get(user_id=instance.id)
        except:

            wallet.objects.create(user_id=instance)
                      
    else:
        print('not verified yet')






class Rank(models.Model):
    rank=models.CharField(max_length=200,unique=True)
    royality_income=models.CharField(max_length=200)
    business_required=models.CharField(max_length=200,default='7500')
    reward=models.CharField(max_length=200,default='android')
    image=models.CharField(max_length=200,default='android.jpg')
    days=models.CharField(max_length=200,default='30')
    status=models.CharField(max_length=100,default='1')
    class Meta:
        db_table='rank'


class Rewards(models.Model):
    rank=models.CharField(max_length=250)
    income=models.CharField(max_length=250)
    business_required=models.CharField(max_length=250)
    days=models.CharField(max_length=250)
    turnover=models.CharField(max_length=200,default='Team')
    status=models.CharField(max_length=250,default='1')
    class Meta:
        db_table = 'rewards'
        

class userRewards(models.Model):
    user_id=models.ForeignKey("core.User", db_column='user_id', on_delete=models.CASCADE)
    rank_id=models.ForeignKey("core.Rewards", db_column='rank_id', on_delete=models.CASCADE,default='1')
    reward_recieved=models.CharField(max_length=200,default='0')
    status=models.CharField(max_length=100,default='0') 
    date=models.CharField(max_length=200,default=datetime.now())
    next_date=models.CharField(max_length=250,default=datetime.now())
    class Meta:
        db_table='userrewards'

class rewardLogs(models.Model):
    rank_id=models.ForeignKey("core.userRewards", db_column='rank_id', on_delete=models.CASCADE)
    reward_recieved=models.CharField(max_length=200,default='0')
    date=models.CharField(max_length=200,default=datetime.now())
    class Meta:
        db_table='rewardlogs'

class cofounderclub(models.Model):
    club=models.CharField(max_length=200,unique=True)
    business=models.CharField(max_length=200)
    reward=models.CharField(max_length=200)
    status=models.CharField(max_length=200,default='1')




class usercofounderclub(models.Model):
    user_id=models.ForeignKey("core.User", db_column='user_id', on_delete=models.CASCADE)
    club_id=models.ForeignKey("core.cofounderclub", db_column='club_id', on_delete=models.CASCADE)
    reward_recieved=models.CharField(max_length=200,default='0')
    status=models.CharField(max_length=100,default='0')
    date=models.CharField(max_length=200,default=datetime.utcnow())



class userRank(models.Model):
    rank_id=models.ForeignKey("core.Rank", db_column='rank_id', on_delete=models.CASCADE)
    user_id=models.ForeignKey("core.User", db_column='user_id', on_delete=models.CASCADE)
    status=models.CharField(max_length=200,default='0')
    reward_recieved=models.CharField(max_length=200,default='0')
    income=models.CharField(max_length=200,default='0')
    date=models.CharField(max_length=200,default=datetime.utcnow())
    class Meta:
        db_table='user_rank'



    

class Login_history(models.Model):
    user_id=models.ForeignKey("core.User", db_column='user_id', on_delete=models.CASCADE)
    login_time=models.CharField(max_length=200)
    logout_time=models.CharField(max_length=200)
    ip_location=models.CharField(max_length=200,default='NA')
    city=models.CharField(max_length=200,default='NA')
    region=models.CharField(max_length=200,default='NA')
    country=models.CharField(max_length=200,default='NA')




class Emailservice(models.Model):
    service=models.CharField(max_length=200)
    host=models.CharField(max_length=200)
    user=models.CharField(max_length=200)
    password=models.CharField(max_length=200)
    port =models.CharField(max_length=200)
    status=models.CharField(max_length=200,default='0')



class youtubevideo(models.Model):
    videolink=models.CharField(max_length=200)
    type=models.CharField(max_length=255,default='1')
    status=models.CharField(max_length=100,default='1')
    sequence=models.CharField(max_length=250,default='0')







