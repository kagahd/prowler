from django.urls import path, include
from drf_spectacular.views import SpectacularRedocView
from rest_framework_nested import routers

from api.v1.views import (
    SchemaView,
    UserViewSet,
    TenantViewSet,
    TenantMembersViewSet,
    MembershipViewSet,
    ProviderViewSet,
    ScanViewSet,
    TaskViewSet,
    ResourceViewSet,
    FindingViewSet,
)

router = routers.DefaultRouter(trailing_slash=False)

router.register(r"users", UserViewSet, basename="user")
router.register(r"tenants", TenantViewSet, basename="tenant")
router.register(r"providers", ProviderViewSet, basename="provider")
router.register(r"scans", ScanViewSet, basename="scan")
router.register(r"tasks", TaskViewSet, basename="task")
router.register(r"resources", ResourceViewSet, basename="resource")
router.register(r"findings", FindingViewSet, basename="finding")

tenants_router = routers.NestedSimpleRouter(router, r"tenants", lookup="tenant")
tenants_router.register(
    r"memberships", TenantMembersViewSet, basename="tenant-membership"
)

users_router = routers.NestedSimpleRouter(router, r"users", lookup="user")
users_router.register(r"memberships", MembershipViewSet, basename="user-membership")

urlpatterns = [
    path("", include(router.urls)),
    path("", include(tenants_router.urls)),
    path("", include(users_router.urls)),
    path("schema", SchemaView.as_view(), name="schema"),
    path("docs", SpectacularRedocView.as_view(url_name="schema"), name="docs"),
]
