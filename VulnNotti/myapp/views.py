from django.views.generic.base import TemplateView
from django.views.generic import FormView
from django.views.generic import View
from django.db import connection
from django.shortcuts import render
from django.http import JsonResponse
from django.http import HttpResponseRedirect
from .forms import UploadFileForm
import re

class DynamicView(TemplateView):
    template_name = 'dynamic.html'

    def get(self, request, *args, **kwargs):

        query = 'SELECT * FROM vuln.dynamic'

        param_list = []

        with connection.cursor() as cursor:
            cursor.execute(query, param_list)

        columns = [column[0] for column in cursor.description]

        object_list = []

        for row in cursor.fetchall():
            object_list.append(dict(zip(columns, row)))

        context = {}

        context['object_list'] = object_list


        # f = open("C:/Users/dlrud/Desktop/shell.txt", 'r')
        # while True:
        #     line = f.readline()
        #     if not line: break
        #     print(line)
        # f.close()

        return render(self.request, self.template_name, context)

    def post(self, request, *args, **kwargs):
        file = request.FILES['sentFile'] # here you get the files needed

        temp = ""

        while True:
            line = file.readline()

            temp += str(line, 'UTF-8')
            if not line: break
            # print(str(line, 'UTF-8'))

            # r = re.compile('\@.+\@', )
        r = re.compile(r'\@(.*?)\@', re.DOTALL)
        results = r.findall(temp)

        result_list = dict(enumerate(results, 0))

        query = 'SELECT * FROM vuln.dynamic'

        param_list = []

        with connection.cursor() as cursor:
            cursor.execute(query, param_list)

        columns = [column[0] for column in cursor.description]

        object_list = []

        for row in cursor.fetchall():
            object_list.append(dict(zip(columns, row)))


        for i in range(0, len(result_list)):
            object_list[i]['result'] = result_list[i]

        context = {}
        context['object_list'] = object_list


        return render(self.request, self.template_name, context)


class StaticView(TemplateView):
    template_name = 'static.html'

    def get(self, request, *args, **kwargs):

        if request.is_ajax():
            data = 1
            idx = request.GET.get('idx')
            method = request.GET.get('method')

            print(idx)
            print(method)
            return JsonResponse(data, safe=False)

        context = {}
        query = 'SELECT * FROM vuln.vulnInfo LIMIT 50'

        param_list = []

        with connection.cursor() as cursor:
            cursor.execute(query, param_list)

        columns = [column[0] for column in cursor.description]

        print(columns)

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

# class ServerList(View):
#     template_name = 'test.html'
#
#     def get(self, request, *args, **kwargs):
#
#         query = 'SELECT * FROM vuln.vulnInfo'
#         param_list = []
#
#         with connection.cursor() as cursor:
#             cursor.execute(query, param_list)
#
#         columns = [column[0] for column in cursor.description]
#
#         for row in cursor.fetchall():
#             object_list.append(dict(zip(columns, row)))
#
#         context = {}
#         object_list = []
#         context['object_list'] = object_list
#
#         return render(self.request, self.template_name, context)
#
# class TableView(TemplateView):
#     template_name = 'myapp_table.html'
