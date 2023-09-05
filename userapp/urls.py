from django.contrib import admin
from django.urls import path,include
from .import views

urlpatterns = [
    path('',views.index),
    path('dashboard',views.home,name='dashboard'),
 
    path('forgot',views.forgot),
    path('otp',views.otp),
    path('change',views.change),
    path('register',views.register),
    path('register/<str:pk>/',views.register),
    path('signout',views.signout,name='signout'),
    path('myprofile',views.userprofile),
    path('myprofile1',views.myprofile),
    path('wallet',views.walletview),
    path('user_referal',views.user_referal),
    path('deposit',views.deposit),
    path('withdraw',views.withdrawal),
    path('income',views.income),
    path('verify/<str:pk>/',views.verifyregister,name='register'),
    path('users',views.userdata),
    path('loginpage',views.loginpage),
    path('package',views.memberships),
    path('support',views.support),
    path('transaction',views.transactions),
    path('users/<str:pk>/',views.userdata),
    path('plan',views.plancontent),
    path('allplans',views.allplans),
    path('get_refferal/<str:pk>/',views.get_reffer_data),
    path('userpackage',views.userpackage),
    path('social-auth/',include('social_django.urls',namespace='social')),
    path('resend_otp/<str:pk>/',views.resend_otp),
    path('loginviagoogle',views.loginviagoogle),
    path('resetpass',views.resetpass),
    path('buyplan',views.buyplan),
    path('transfer',views.ptransfer),
    path('transferhistory',views.transferhistory),
    path('roi_history',views.roi_history),
    path('level_income',views.level_income),
    path('about',views.about),
    path('wallettransfer',views.wallettransfer),
    path('startincome',views.dailyincome.as_view()),
    path('current_farming',views.current_farming),
    path('current_staking',views.current_staking),
    path('packages',views.packages),
    path('gallery',views.gallery),
    path('rankreward',views.rankreward),
    path('direct_income',views.direct_income),
    path('deposithistory',views.depostihistory),
    path('withdrawhistory',views.withdrawalihistory),
    path('tophistory',views.topuphistory),
    path('tree',views.tree),
    path('downlineteam',views.downlineteam),
    path('reset_password/<str:pk>/',views.reset_password),
    path('newpassword',views.newpassword)

    



]