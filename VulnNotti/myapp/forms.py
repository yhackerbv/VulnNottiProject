from django import forms

class testform(forms.Form):
    text = forms.CharField(max_length=100, widget=forms.TextInput(attrs={'size':80}))
