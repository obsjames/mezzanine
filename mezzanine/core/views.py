import os
from urlparse import urljoin, urlparse

from django.contrib import admin
from django.contrib.admin.views.decorators import staff_member_required
from django.contrib.admin.options import ModelAdmin
from django.contrib.staticfiles import finders
from django.core.exceptions import PermissionDenied
from django.core.urlresolvers import reverse
from django.db.models import get_model
from django.http import (HttpResponse, HttpResponseServerError,
                         HttpResponseNotFound)
from django.shortcuts import redirect
from django.template import RequestContext
from django.template.loader import get_template
from django.utils.translation import ugettext_lazy as _
from django.views.decorators.csrf import requires_csrf_token

from mezzanine.conf import settings
from mezzanine.core.forms import get_edit_form
from mezzanine.core.models import Displayable, SitePermission
from mezzanine.utils.cache import add_cache_bypass
from mezzanine.utils.views import is_editable, paginate, render, set_cookie
from mezzanine.utils.sites import has_site_permission
from mezzanine.utils.urls import next_url

from cartridge.shop.models import Product, Store
from django.http import HttpResponseRedirect
from django.template.defaultfilters import slugify
from django.contrib.messages import info

from stores.checkout import find_stores
from stores.location_utils import getAddress, getLocation
from stores.forms import StoreFilterForm

def set_device(request, device=""):
    """
    Sets a device name in a cookie when a user explicitly wants to go
    to the site for a particular device (eg mobile).
    """
    response = redirect(add_cache_bypass(next_url(request) or "/"))
    set_cookie(response, "mezzanine-device", device, 60 * 60 * 24 * 365)
    return response


@staff_member_required
def set_site(request):
    """
    Put the selected site ID into the session - posted to from
    the "Select site" drop-down in the header of the admin. The
    site ID is then used in favour of the current request's
    domain in ``mezzanine.core.managers.CurrentSiteManager``.
    """
    site_id = int(request.GET["site_id"])
    if not request.user.is_superuser:
        try:
            SitePermission.objects.get(user=request.user, sites=site_id)
        except SitePermission.DoesNotExist:
            raise PermissionDenied
    request.session["site_id"] = site_id
    admin_url = reverse("admin:index")
    next = next_url(request) or admin_url
    # Don't redirect to a change view for an object that won't exist
    # on the selected site - go to its list view instead.
    if next.startswith(admin_url):
        parts = next.split("/")
        if len(parts) > 4 and parts[4].isdigit():
            next = "/".join(parts[:4])
    return redirect(next)


def direct_to_template(request, template, extra_context=None, **kwargs):
    """
    Replacement for Django's ``direct_to_template`` that uses
    ``TemplateResponse`` via ``mezzanine.utils.views.render``.
    """
    context = extra_context or {}
    context["params"] = kwargs
    for (key, value) in context.items():
        if callable(value):
            context[key] = value()
    return render(request, template, context)


@staff_member_required
def edit(request):
    """
    Process the inline editing form.
    """
    model = get_model(request.POST["app"], request.POST["model"])
    obj = model.objects.get(id=request.POST["id"])
    form = get_edit_form(obj, request.POST["fields"], data=request.POST,
                         files=request.FILES)
    if not (is_editable(obj, request) and has_site_permission(request.user)):
        response = _("Permission denied")
    elif form.is_valid():
        form.save()
        model_admin = ModelAdmin(model, admin.site)
        message = model_admin.construct_change_message(request, form, None)
        model_admin.log_change(request, obj, message)
        response = ""
    else:
        response = form.errors.values()[0][0]
    return HttpResponse(unicode(response))


def search(request, template="search_results.html"):
    """
    Display search results. Takes an optional "contenttype" GET parameter
    in the form "app-name.ModelName" to limit search results to a single model.
    """

    if 'new location' not in request.session and 'location' not in request.session:
        info(request, _("Enter your location to use the search"))
        return HttpResponseRedirect('/')

#    elif 'new location' in request.session and 'age' in request.session:
#        loc = getLocation(request.session['new location'])
#        request.session['location'] = (loc[0],loc[1])
#        address = getAddress(loc[0],loc[1])
#        request.session['address'] = address
#        del request.session['new location']

    elif 'location' in request.session and 'age' in request.session:
        loc = request.session['location']

    else:
        return HttpResponseRedirect('/')

    if 'new query' in request.session:
	del request.session['new query']
	map_required = True
#	request.session['map'] = True	
    elif 'map' in request.session:
    	map_required = True
        del request.session['map']
    else:
        map_required = False

    address = request.session['address']
    if 'cart loaded' in request.session:
        current_store = request.session['stores'][0]
	store_slug = request.session['store slug']
    else:
	current_store, store_slug = [], []

    settings.use_editable()
    query = request.GET.get("q", "")
    if not query:
	if 'query' in request.session:
	    query = request.session['query']
    page = request.GET.get("page", 1)
    per_page = settings.SEARCH_PER_PAGE
    max_paging_links = settings.MAX_PAGING_LINKS
    try:
        search_model = get_model(*request.GET.get("type", "").split(".", 1))
        if not issubclass(search_model, Displayable):
            raise TypeError
    except TypeError:
        search_model = Displayable
        search_type = _("Everything")
    else:
        search_type = search_model._meta.verbose_name_plural.capitalize()
    results = search_model.objects.search(query, for_user=request.user)

    delivery_mins = []

    if 'cart loaded' in request.session:
    	stores = request.session['stores']
	store_locs, form = [], []
	filter_form, cart_loaded = False, True

    else:
	filter_form, cart_loaded = True, False

    	displayed_stores = []
    	for result in results:
            if result.store.name not in displayed_stores:
            	delivery_mins.append(str(result.store.delivery_min))     #####
            	displayed_stores.append(result.store.name)

        if 'store ids' in request.session:
            avail_store_ids, avail_store_names, store_locs = request.session['store ids'], request.session['store names'], request.session['store locs']
        else:
            avail_store_ids, avail_store_names, store_locs, closed_store_ids, closed_store_names, closed_locs = find_stores(request, loc)

        if avail_store_ids:

	    stores = []

            if request.method == 'POST': # If the form has been submitted...
		form = StoreFilterForm(request.POST, stores=displayed_stores, delivery=delivery_mins)
                if form.is_valid():
		     for name in displayed_stores:
			if form.cleaned_data["%s" % name]:
			    stores.extend(Store.objects.filter(name__exact="%s" % name))

		if not stores:
		    stores = Store.objects.filter(id__in=avail_store_ids)
	    else:
            	form = StoreFilterForm(stores=displayed_stores, delivery=delivery_mins)
            	stores = Store.objects.filter(id__in=avail_store_ids)
        else:
            return HttpResponseRedirect('/shop/')    ######!

    avail_prod_ids = []
    for p in stores:
    	for k in results:
            if p == k.store:
      		avail_prod_ids.append(k.id)

    results = Product.objects.filter(id__in=avail_prod_ids)
    sort_options = [(slugify(option[0]), option[1])
                for option in settings.SHOP_PRODUCT_SORT_OPTIONS]
    sort_by = request.GET.get("sort", sort_options[0][1])

    if sort_by=='-date_added':
	request.session['query'] = query

    results = paginate(results.order_by(sort_by),
                    request.GET.get("page", 1),
                    settings.SHOP_PER_PAGE_CATEGORY,
                    settings.MAX_PAGING_LINKS)
    results.sort_by = sort_by

#    paginated = paginate(results, page, per_page, max_paging_links)
    paginated = results
    context = {"query": query, "results": paginated, 'map': map_required, 'lat': loc[0], 'lon': loc[1], "form_name": 'Stores',
               "search_type": search_type, 'store_locs': store_locs, "form": form, "filter_form": filter_form,
	       "cart_loaded": cart_loaded, "delivery_mins": delivery_mins, "address": address, "stores": current_store,
	       "store_slug": store_slug, 'closed_locs': closed_locs}

    return render(request, template, context)

@staff_member_required
def static_proxy(request):
    """
    Serves TinyMCE plugins inside the inline popups and the uploadify
    SWF, as these are normally static files, and will break with
    cross-domain JavaScript errors if ``STATIC_URL`` is an external
    host. URL for the file is passed in via querystring in the inline
    popup plugin template.
    """
    # Get the relative URL after STATIC_URL.
    url = request.GET["u"]
    protocol = "http" if not request.is_secure() else "https"
    host = protocol + "://" + request.get_host()
    generic_host = "//" + request.get_host()
    # STATIC_URL often contains host or generic_host, so remove it
    # first otherwise the replacement loop below won't work.
    static_url = settings.STATIC_URL.replace(host, "", 1)
    static_url = static_url.replace(generic_host, "", 1)
    for prefix in (host, generic_host, static_url, "/"):
        if url.startswith(prefix):
            url = url.replace(prefix, "", 1)
    response = ""
    mimetype = ""
    path = finders.find(url)
    if path:
        if isinstance(path, (list, tuple)):
            path = path[0]
        with open(path, "rb") as f:
            response = f.read()
        mimetype = "application/octet-stream"
        if url.endswith(".htm"):
            # Inject <base href="{{ STATIC_URL }}"> into TinyMCE
            # plugins, since the path static files in these won't be
            # on the same domain.
            mimetype = "text/html"
            static_url = settings.STATIC_URL + os.path.split(url)[0] + "/"
            if not urlparse(static_url).scheme:
                static_url = urljoin(host, static_url)
            base_tag = "<base href='%s'>" % static_url
            response = response.replace("<head>", "<head>" + base_tag)
    return HttpResponse(response, mimetype=mimetype)


@requires_csrf_token
def page_not_found(request, template_name="errors/404.html"):
    """
    Mimics Django's 404 handler but with a different template path.
    """
    context = RequestContext(request, {
        "STATIC_URL": settings.STATIC_URL,
        "request_path": request.path,
    })
    t = get_template(template_name)
    return HttpResponseNotFound(t.render(context))


@requires_csrf_token
def server_error(request, template_name="errors/500.html"):
    """
    Mimics Django's error handler but adds ``STATIC_URL`` to the
    context.
    """
    context = RequestContext(request, {"STATIC_URL": settings.STATIC_URL})
    t = get_template(template_name)
    return HttpResponseServerError(t.render(context))
