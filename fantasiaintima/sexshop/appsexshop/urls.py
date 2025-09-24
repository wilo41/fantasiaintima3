"""
URL configuration for sexshop project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from django.urls import path, include 
from appsexshop.views import (
    LadingPage, listadocategorias, insertarcategorias, borrarcategoria, actualizarcategoria, 
    perfiles, crudCategorias, crudSubCategorias, crudProductos, crudDomiciliarios, crudUsuarios, 
    login, registro, solicitar_recuperacion, pedido, verificar_codigo, 	nueva_contrasena,
    insertarsubcategoria, listadosubcategorias, borrarsubcategoria, actualizarsubcategoria,editarusuario,
    borrarusuario, insertarusuario, carrito, lencerias, productosCarrito, insertardomiciliario, editardomiciliario, borrardomiciliario,
    insertarproducto, editarproducto, borrarproducto, vibradores, disfraces, dildos, logout, eliminar_foto_perfil, eliminar_cuenta, guardar_calificacion, agregar_al_carrito, lista_notificaciones, marcar_leida, pago_paypal_carrito,
    pago_cancelado, pago_exitoso, detalles_pedido, cancelar_pedido, solicitud, cambiar_estado_pedido, productos_por_subcategoria, obtener_carrito_usuario, registrar_pago, productos_por_pedido_view
)

urlpatterns = [
    path('', LadingPage, name='Ladingpage'),
    path('perfiles/', perfiles, name='perfiles'),
    path('eliminar-foto-perfil/', eliminar_foto_perfil, name='eliminar_foto_perfil'),
    path('listadocategorias/', listadocategorias, name='listadocategorias'),
    path('insertarcategorias/', insertarcategorias, name='insertarcategorias'),
    path('categorias/borrar/<int:id_categoria>/', borrarcategoria, name='borrarcategoria'),
    path('categorias/actualizar/<int:id_categoria>/', actualizarcategoria, name='actualizarcategoria'),
    path('crud/categorias', crudCategorias,  name='crudCategorias'),
    path('crud/subcategorias', crudSubCategorias, name='crudSubCategorias'),
    path('subcategorias/insertar/', insertarsubcategoria, name='insertarsubcategoria'),
    path('subcategorias/listado/', listadosubcategorias, name='listadosubcategorias'),
    path('subcategorias/borrar/<int:id_subcategoria>/', borrarsubcategoria, name='borrarsubcategoria'),
    path('subcategorias/actualizar/<int:id_subcategoria>/', actualizarsubcategoria, name='actualizarsubcategoria'),
    path('crud/productos', crudProductos, name='crudProductos'),
    path('crud/productos/insertar/', insertarproducto, name='insertarproducto'),
    path('crud/productos/editar/<int:id_producto>/', editarproducto, name='editarproducto'),
    path('crud/productos/eliminar/<int:id_producto>/', borrarproducto, name='borrarproducto'),
    path('crud/domiciliarios', crudDomiciliarios, name='crudDomiciliarios'),
    path('crud/domiciliarios/insertar/', insertardomiciliario, name='insertardomiciliario'),
    path('crud/domiciliarios/editar/<int:id_domiciliario>/', editardomiciliario, name='editardomiciliario'),
    path('crud/domiciliarios/eliminar/<int:id_domiciliario>/', borrardomiciliario, name='borrardomiciliario'),
    path('crud/usuarios', crudUsuarios, name='crudUsuarios'),
    path('crud/usuarios/insertar/', insertarusuario, name='insertarusuario'),
    path('crud/usuarios/editar/<int:id_usuario>/', editarusuario, name='actualizarusuario'),
    path('crud/usuarios/eliminar/<int:id_usuario>/', borrarusuario, name='borrarusuario'),
    path('login/', login, name='login'),
    path('logout/', logout, name='logout'),
    path('registro/', registro, name='registro'),
    path('recuperarContraseña', solicitar_recuperacion, name='solicitar_recuperacion'),
    path('codigo', verificar_codigo, name='verificar_codigo'),
    path('nuevaContraseña',nueva_contrasena, name='nueva_contrasena'),
    path('pedido', pedido, name='pedido'),
    path('carrito', carrito, name='carrito'),
    path('lencerias', lencerias, name='lencerias'),
    path('vibradores', vibradores, name='vibradores'),
    path('disfraces', disfraces, name='disfraces'),
    path('dildos', dildos, name='dildos'),
    path('productos', productosCarrito, name='productosCarrito'),
    path('eliminar-cuenta/', eliminar_cuenta, name='eliminar_cuenta'),
    path('guardar-calificacion/', guardar_calificacion, name='guardar_calificacion'),
     path('agregar-al-carrito/<int:producto_id>/', agregar_al_carrito, name="agregar_al_carrito"),
     path('notificaciones/', lista_notificaciones, name='lista_notificaciones'),
     path('notificaciones/marcar_leida/<int:id_notificacion>/', marcar_leida, name='marcar_leida'),

     path('pago-paypal-carrito/', pago_paypal_carrito, name='pago_paypal_carrito'),
    path('paypal/', include('paypal.standard.ipn.urls')),
    path('pago-exitoso/', pago_exitoso, name='pago_exitoso'),
    path('pago-cancelado/', pago_cancelado, name='pago_cancelado'),
    path('pedidos/<str:codigo_pedido>/', detalles_pedido, name='detalles_pedido'),
    path('pedidos/cancelar/<str:codigo_pedido>/', cancelar_pedido, name='cancelar_pedido'),
    path('solicitud/', solicitud, name='solicitud'),
    path('cambiar-estado/<str:codigo_pedido>/', cambiar_estado_pedido, name='cambiar_estado_pedido'),
    path('productos/subcategoria/<int:id_subcategoria>/', productos_por_subcategoria, name='productos_por_subcategoria'),
    path('api/obtener-carrito-usuario/', obtener_carrito_usuario, name='obtener_carrito_usuario'), 
    path('registrar-pago/', registrar_pago, name='registrar_pago'),
    path('productos-por-pedido/<int:pedido_id>/', productos_por_pedido_view, name='productos_por_pedido'),

]


   


if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
