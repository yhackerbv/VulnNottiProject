from django.views.generic.base import TemplateView
from django.views.generic.edit import CreateView
from django.views import View
from django.urls import reverse_lazy
from django.contrib.auth.forms import UserCreationForm
from django.http import HttpResponseRedirect, HttpResponse
from VulnNotti.forms import *;
from django.shortcuts import redirect, render

class HomeView(View):
    template_name = 'index.html'

    def get(self, request, *args, **kwargs):

        # if not request.user.is_authenticated(): # 로그인한 사용자만 가능
        #     return HttpResponseRedirect(reverse('login'))
        #
        # query = 'SELECT name, code FROM server WHERE 1=1'
        # param_list = []
        #
        # with connection.cursor() as cursor:
        #     cursor.execute(query, param_list)
        #
        #     columns = [column[0] for column in cursor.description]
        #     object_list = []
        #
        #     for row in cursor.fetchall():
        #         object_list.append(dict(zip(columns, row)))
        #
        #     context = {}
        #     context['form'] = ServerList_form
        #     context['object_list'] = object_list



        return render(self.request, self.template_name)

    def post(self, request, *args, **kwargs):

        name = self.request.POST['name']
        email = self.request.POST['email']
        phone = self.request.POST['phone']
        message = self.request.POST['message']

        print(name, email, phone, message)


        return render(self.request, self.template_name)


    #     form = self.form_class(request.POST)
    #     instance = self.request.POST['instance']
    #     ipaddr = self.request.POST['ipaddr']
    #
    #     query = "INSERT INTO mysqldb VALUES (%s, %s);"
    #     param_list = []
    #     param_list.append(instance, ipaddr)
    #
    #     with connection.cursor() as cursor:
    #         cursor.execute(query, param_list)



class UserCreateView(CreateView):
    template_name = 'registration/register.html'
    success_url = reverse_lazy('register_done')
    form_class = UserCreationForm

class UserCreateDoneTV(TemplateView):
    template_name = 'registration/register_done.html'
