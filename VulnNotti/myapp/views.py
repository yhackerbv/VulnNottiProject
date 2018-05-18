from django.views.generic.base import TemplateView
from django.views.generic import FormView
from django.views.generic import View
from myapp.forms import testform
from django.db import connection
from django.shortcuts import render


class MypageView(TemplateView):
    template_name = 'mypage.html'
    form_class = testform

    def get(self, request, *args, **kwargs):
        context = {}
        context['form'] = testform

        query = 'SELECT * FROM vuln.vulnInfo'

        param_list = []

        with connection.cursor() as cursor:
            cursor.execute(query, param_list)

        columns = [column[0] for column in cursor.description]

        object_list = []

        for row in cursor.fetchall():
            object_list.append(dict(zip(columns, row)))

        context = {}

        red = 3
        blue = 4
        green = 5

        context['red'] = red
        context['blue'] = blue
        context['green'] = green 
        context['object_list'] = object_list

        return render(self.request, self.template_name, context)


    def post(self, request, *args, **kwargs):
        text = self.request.POST['text']
        context = {}
        context['form'] = testform
        print(text)
        return render(self.request, self.template_name, context)

class ServerList(View):
    template_name = 'test.html'

    def get(self, request, *args, **kwargs):

        query = 'SELECT * FROM vuln.vulnInfo'
        param_list = []

        with connection.cursor() as cursor:
            cursor.execute(query, param_list)

        columns = [column[0] for column in cursor.description]

        for row in cursor.fetchall():
            object_list.append(dict(zip(columns, row)))

        context = {}
        object_list = []
        context['object_list'] = object_list

        return render(self.request, self.template_name, context)

class TableView(TemplateView):
    template_name = 'myapp_table.html'
