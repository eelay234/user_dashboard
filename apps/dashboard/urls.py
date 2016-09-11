from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^users/admin/update_password/(\d+)$', views.admin_update_password),
    url(r'^users/admin/update_info/(\d+)$', views.admin_update_info),
    url(r'^users/admin/remove/(\d+)$', views.remove),
    url(r'^users/admin/edit/(\d+)$', views.admin_edit),
    url(r'^users/new$', views.new),
    url(r'^users/post_comment/(\d+)/(\d+)$', views.post_comment),
    url(r'^users/post/(\d+)$', views.post),
    url(r'^dashboard/(\d+)$', views.show_dashboard),
    url(r'^users/show/(\d+)$', views.show),
    #url(r'^users/show/(?P<id>\d+)$', views.show),
    url(r'^users/update_description/(?P<id>\d+)$', views.update_description),
    url(r'^users/update_password/(?P<id>\d+)$', views.update_password),
    url(r'^users/update_info/(?P<id>\d+)$', views.update_info),
    url(r'^users/edit$', views.edit),
    url(r'^registration$', views.registration),
    url(r'^show_dashboard$', views.show_dashboard),
    url(r'^register$', views.register),
    url(r'^logoff$', views.logoff),
    url(r'^login$', views.login),
    url(r'^signin$', views.signin),
    url(r'^$', views.index)
]
