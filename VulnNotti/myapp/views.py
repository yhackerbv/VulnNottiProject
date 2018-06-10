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
        query = 'SELECT * FROM vuln.vulnDetail WHERE username = %s'

        param_list = []
        query += 'LIMIT 100'
        param_list.append(str(request.user))

        with connection.cursor() as cursor:
            cursor.execute(query, param_list)

        columns = [column[0] for column in cursor.description]

        object_list = []

        for row in cursor.fetchall():
            object_list.append(dict(zip(columns, row)))


        context['object_list'] = object_list



        query = 'SELECT COUNT(year) FROM vuln.vulnDetail WHERE year="2009" AND username = %s'
        param_list = []
        param_list.append(str(request.user))

        with connection.cursor() as cursor:
            cursor.execute(query, param_list)
        temp_list = []
        for row in cursor.fetchall():
            temp_list.append(dict(zip(columns, row)))

        year2009 = temp_list[0]['index']

        query = 'SELECT COUNT(year) FROM vuln.vulnDetail WHERE year="2010" AND username = %s'
        param_list = []
        param_list.append(str(request.user))

        with connection.cursor() as cursor:
            cursor.execute(query, param_list)
        temp_list = []
        for row in cursor.fetchall():
            temp_list.append(dict(zip(columns, row)))

        year2010 = temp_list[0]['index']

        query = 'SELECT COUNT(year) FROM vuln.vulnDetail WHERE year="2011" AND username = %s'
        param_list = []
        param_list.append(str(request.user))

        with connection.cursor() as cursor:
            cursor.execute(query, param_list)
        temp_list = []
        for row in cursor.fetchall():
            temp_list.append(dict(zip(columns, row)))

        year2011 = temp_list[0]['index']

        query = 'SELECT COUNT(year) FROM vuln.vulnDetail WHERE year="2012" AND username = %s'
        param_list = []
        param_list.append(str(request.user))

        with connection.cursor() as cursor:
            cursor.execute(query, param_list)
        temp_list = []
        for row in cursor.fetchall():
            temp_list.append(dict(zip(columns, row)))

        year2012 = temp_list[0]['index']

        query = 'SELECT COUNT(year) FROM vuln.vulnDetail WHERE year="2013" AND username = %s'
        param_list = []
        param_list.append(str(request.user))

        with connection.cursor() as cursor:
            cursor.execute(query, param_list)
        temp_list = []
        for row in cursor.fetchall():
            temp_list.append(dict(zip(columns, row)))

        year2013 = temp_list[0]['index']

        query = 'SELECT COUNT(year) FROM vuln.vulnDetail WHERE year="2014" AND username = %s'
        param_list = []
        param_list.append(str(request.user))

        with connection.cursor() as cursor:
            cursor.execute(query, param_list)
        temp_list = []
        for row in cursor.fetchall():
            temp_list.append(dict(zip(columns, row)))

        year2014 = temp_list[0]['index']

        query = 'SELECT COUNT(year) FROM vuln.vulnDetail WHERE year="2015" AND username = %s'
        param_list = []
        param_list.append(str(request.user))

        with connection.cursor() as cursor:
            cursor.execute(query, param_list)
        temp_list = []
        for row in cursor.fetchall():
            temp_list.append(dict(zip(columns, row)))

        year2015 = temp_list[0]['index']

        query = 'SELECT COUNT(year) FROM vuln.vulnDetail WHERE year="2016" AND username = %s'
        param_list = []
        param_list.append(str(request.user))

        with connection.cursor() as cursor:
            cursor.execute(query, param_list)
        temp_list = []
        for row in cursor.fetchall():
            temp_list.append(dict(zip(columns, row)))

        year2016 = temp_list[0]['index']

        query = 'SELECT COUNT(year) FROM vuln.vulnDetail WHERE year="2017" AND username = %s'
        param_list = []
        param_list.append(str(request.user))

        with connection.cursor() as cursor:
            cursor.execute(query, param_list)
        temp_list = []
        for row in cursor.fetchall():
            temp_list.append(dict(zip(columns, row)))

        year2017 = temp_list[0]['index']

        query = 'SELECT COUNT(year) FROM vuln.vulnDetail WHERE year="2018" AND username = %s'
        param_list = []
        param_list.append(str(request.user))

        with connection.cursor() as cursor:
            cursor.execute(query, param_list)
        temp_list = []
        for row in cursor.fetchall():
            temp_list.append(dict(zip(columns, row)))

        year2018 = temp_list[0]['index']

        query = 'SELECT COUNT(year) FROM vuln.vulnDetail WHERE year="2018" AND username = %s'
        param_list = []
        param_list.append(str(request.user))

        with connection.cursor() as cursor:
            cursor.execute(query, param_list)
        temp_list = []
        for row in cursor.fetchall():
            temp_list.append(dict(zip(columns, row)))

        year2018 = temp_list[0]['index']

        query = 'SELECT COUNT(ROUND(level)) FROM vuln.vulnDetail WHERE level >= 0 AND level < 1 AND username = %s'
        param_list = []
        param_list.append(str(request.user))

        with connection.cursor() as cursor:
            cursor.execute(query, param_list)
        temp_list = []
        for row in cursor.fetchall():
            temp_list.append(dict(zip(columns, row)))

        level0 = temp_list[0]['index']

        query = 'SELECT COUNT(ROUND(level)) FROM vuln.vulnDetail WHERE level >= 1 AND level < 2 AND username = %s'
        param_list = []
        param_list.append(str(request.user))

        with connection.cursor() as cursor:
            cursor.execute(query, param_list)
        temp_list = []
        for row in cursor.fetchall():
            temp_list.append(dict(zip(columns, row)))

        level1 = temp_list[0]['index']

        query = 'SELECT COUNT(ROUND(level)) FROM vuln.vulnDetail WHERE level >= 2 AND level < 3 AND username = %s'
        param_list = []
        param_list.append(str(request.user))

        with connection.cursor() as cursor:
            cursor.execute(query, param_list)
        temp_list = []
        for row in cursor.fetchall():
            temp_list.append(dict(zip(columns, row)))

        level2 = temp_list[0]['index']

        query = 'SELECT COUNT(ROUND(level)) FROM vuln.vulnDetail WHERE level >= 3 AND level < 4 AND username = %s'
        param_list = []
        param_list.append(str(request.user))

        with connection.cursor() as cursor:
            cursor.execute(query, param_list)
        temp_list = []
        for row in cursor.fetchall():
            temp_list.append(dict(zip(columns, row)))

        level3 = temp_list[0]['index']

        query = 'SELECT COUNT(ROUND(level)) FROM vuln.vulnDetail WHERE level >= 4 AND level < 5 AND username = %s'
        param_list = []
        param_list.append(str(request.user))

        with connection.cursor() as cursor:
            cursor.execute(query, param_list)
        temp_list = []
        for row in cursor.fetchall():
            temp_list.append(dict(zip(columns, row)))

        level4 = temp_list[0]['index']

        query = 'SELECT COUNT(ROUND(level)) FROM vuln.vulnDetail WHERE level >= 5 AND level < 6 AND username = %s'
        param_list = []
        param_list.append(str(request.user))

        with connection.cursor() as cursor:
            cursor.execute(query, param_list)
        temp_list = []
        for row in cursor.fetchall():
            temp_list.append(dict(zip(columns, row)))

        level5 = temp_list[0]['index']

        query = 'SELECT COUNT(ROUND(level)) FROM vuln.vulnDetail WHERE level >= 6 AND level < 7 AND username = %s'
        param_list = []
        param_list.append(str(request.user))

        with connection.cursor() as cursor:
            cursor.execute(query, param_list)
        temp_list = []
        for row in cursor.fetchall():
            temp_list.append(dict(zip(columns, row)))

        level6 = temp_list[0]['index']

        query = 'SELECT COUNT(ROUND(level)) FROM vuln.vulnDetail WHERE level >= 7 AND level < 8 AND username = %s'
        param_list = []
        param_list.append(str(request.user))

        with connection.cursor() as cursor:
            cursor.execute(query, param_list)
        temp_list = []
        for row in cursor.fetchall():
            temp_list.append(dict(zip(columns, row)))

        level7 = temp_list[0]['index']

        query = 'SELECT COUNT(ROUND(level)) FROM vuln.vulnDetail WHERE level >= 8 AND level < 9 AND username = %s'
        param_list = []
        param_list.append(str(request.user))

        with connection.cursor() as cursor:
            cursor.execute(query, param_list)
        temp_list = []
        for row in cursor.fetchall():
            temp_list.append(dict(zip(columns, row)))

        level8 = temp_list[0]['index']

        query = 'SELECT COUNT(ROUND(level)) FROM vuln.vulnDetail WHERE level >= 9 AND level < 10 AND username = %s'
        param_list = []
        param_list.append(str(request.user))

        with connection.cursor() as cursor:
            cursor.execute(query, param_list)
        temp_list = []
        for row in cursor.fetchall():
            temp_list.append(dict(zip(columns, row)))

        level9 = temp_list[0]['index']

        query = 'SELECT COUNT(type) FROM vuln.vulnDetail WHERE type=%s AND username = %s'
        param_list = []
        param_list.append(str('NORMAL'))
        param_list.append(str(request.user))

        with connection.cursor() as cursor:
            cursor.execute(query, param_list)
        temp_list = []
        for row in cursor.fetchall():
            temp_list.append(dict(zip(columns, row)))

        NORMAL = int(temp_list[0]['index'])

        query = 'SELECT COUNT(type) FROM vuln.vulnDetail WHERE type=%s AND username = %s'
        param_list = []
        param_list.append(str('OVERFLOW'))
        param_list.append(str(request.user))

        with connection.cursor() as cursor:
            cursor.execute(query, param_list)
        temp_list = []
        for row in cursor.fetchall():
            temp_list.append(dict(zip(columns, row)))

        OVERFLOW = temp_list[0]['index']

        query = 'SELECT COUNT(type) FROM vuln.vulnDetail WHERE type=%s AND username = %s'
        param_list = []
        param_list.append(str('NORMAL'))
        param_list.append(str(request.user))

        with connection.cursor() as cursor:
            cursor.execute(query, param_list)
        temp_list = []
        param_list.append(str('XSS'))
        for row in cursor.fetchall():
            temp_list.append(dict(zip(columns, row)))

        XSS = temp_list[0]['index']

        query = 'SELECT COUNT(type) FROM vuln.vulnDetail WHERE type=%s AND username = %s'
        param_list = []
        param_list.append(str('SQLINJECTION'))
        param_list.append(str(request.user))

        with connection.cursor() as cursor:
            cursor.execute(query, param_list)
        temp_list = []
        for row in cursor.fetchall():
            temp_list.append(dict(zip(columns, row)))

        SQLINJECTION = temp_list[0]['index']

        query = 'SELECT COUNT(type) FROM vuln.vulnDetail WHERE type=%s AND username = %s'
        param_list = []
        param_list.append(str('DOS'))
        param_list.append(str(request.user))

        with connection.cursor() as cursor:
            cursor.execute(query, param_list)
        temp_list = []
        for row in cursor.fetchall():
            temp_list.append(dict(zip(columns, row)))

        DOS = temp_list[0]['index']

        query = 'SELECT COUNT(type) FROM vuln.vulnDetail WHERE type=%s AND username = %s'
        param_list = []
        param_list.append(str('MEMORY'))
        param_list.append(str(request.user))

        with connection.cursor() as cursor:
            cursor.execute(query, param_list)
        temp_list = []
        for row in cursor.fetchall():
            temp_list.append(dict(zip(columns, row)))

        MEMORY = temp_list[0]['index']

        query = 'SELECT COUNT(type) FROM vuln.vulnDetail WHERE type=%s AND username = %s'
        param_list = []
        param_list.append(str('CSRF'))
        param_list.append(str(request.user))

        with connection.cursor() as cursor:
            cursor.execute(query, param_list)
        temp_list = []
        for row in cursor.fetchall():
            temp_list.append(dict(zip(columns, row)))

        CSRF = temp_list[0]['index']

        query = 'SELECT COUNT(type) FROM vuln.vulnDetail WHERE type=%s AND username = %s'
        param_list = []
        param_list.append(str('FILEINCLUSION'))
        param_list.append(str(request.user))

        with connection.cursor() as cursor:
            cursor.execute(query, param_list)
        temp_list = []
        for row in cursor.fetchall():
            temp_list.append(dict(zip(columns, row)))

        FILEINCLUSION = temp_list[0]['index']

        query = 'SELECT COUNT(type) FROM vuln.vulnDetail WHERE type=%s AND username = %s'
        param_list = []
        param_list.append(str('EXCUTE'))
        param_list.append(str(request.user))

        with connection.cursor() as cursor:
            cursor.execute(query, param_list)
        temp_list = []
        for row in cursor.fetchall():
            temp_list.append(dict(zip(columns, row)))

        EXCUTE = temp_list[0]['index']




        context['DOS'] = DOS
        context['OVERFLOW'] = OVERFLOW
        context['XSS'] = XSS
        context['SQLINJECTION'] = SQLINJECTION
        context['CSRF'] = CSRF
        context['FILEINCLUSION'] = FILEINCLUSION
        context['MEMORY'] = MEMORY
        context['EXCUTE'] = EXCUTE
        context['NORMAL'] = NORMAL
        # context['OVERFLOW'] = OVERFLOW
        # context['XSS'] = XSS
        # context['SQLINJECTION'] = SQLINJECTION
        # context['CSRF'] = CSRF
        # context['FILEINCLUSION'] = FILEINCLUSION
        # context['MEMORY'] = MEMORY
        # context['EXCUTE'] = EXCUTE
        # context['NORMAL'] = NORMAL

        context['year2009'] = year2009
        context['year2010'] = year2010
        context['year2011'] = year2011
        context['year2012'] = year2012
        context['year2013'] = year2013
        context['year2014'] = year2014
        context['year2015'] = year2015
        context['year2016'] = year2016
        context['year2017'] = year2017
        context['year2018'] = year2018

        context['level0'] = level0
        context['level1'] = level1
        context['level2'] = level2
        context['level3'] = level3
        context['level4'] = level4
        context['level5'] = level5
        context['level6'] = level6
        context['level7'] = level7
        context['level8'] = level8
        context['level9'] = level9

        context['logined_user'] = str(request.user)


        return render(self.request, self.template_name, context)
