
from django.db import models
import random
from datetime import datetime, timedelta
import string
from django.utils import timezone
from django.contrib.auth.models import User
import json
from django.core.serializers.json import DjangoJSONEncoder

class categoria(models.Model):
    IdCategoria = models.AutoField(primary_key=True)  
    NombreCategoria = models.CharField(max_length=80)

    class Meta:
        db_table = 'categoria'


class subcategoria(models.Model):
    IdSubCategoria = models.AutoField(primary_key=True)  
    NombresubCategoria = models.CharField(max_length=45)
    categoria = models.ForeignKey('categoria', on_delete=models.CASCADE, db_column='IdCategoria')  

    class Meta:
        db_table = 'subcategoria'

class usuario(models.Model):
    IdUsuario  = models.AutoField(primary_key=True)  
    PrimerNombre = models.CharField(max_length=255)
    OtrosNombres = models.CharField(max_length=255)
    PrimerApellido = models.CharField(max_length=255)
    SegundoApellido = models.CharField(max_length=255)
    Correo = models.EmailField(max_length=255, unique=True)
    NombreUsuario  = models.CharField(max_length=45)
    Contrasena   = models.CharField(max_length=128)
    idRol = models.ForeignKey('roles', on_delete=models.CASCADE, db_column='IdRol')
    imagen_perfil = models.ImageField(upload_to='profile_images/', null=True, blank=True)
    class Meta:
        db_table = 'usuario'


class roles(models.Model):
    IdRol = models.AutoField(primary_key=True)  
    TipoRol = models.CharField(max_length=30)
    class Meta:
        db_table = 'roles'

class domiciliario(models.Model):
    IdDomiciliario = models.AutoField(primary_key=True)
    TipoDocumento = models.CharField(max_length=45)
    Documento = models.IntegerField(unique=True)
    NombreDomiciliario = models.CharField(max_length=100)
    PrimerApellido = models.CharField(max_length=45)
    SegundoApellido = models.CharField(max_length=45, blank=True, null=True)
    Celular = models.BigIntegerField()
    Ciudad = models.CharField(max_length=45, blank=True, null=True)
    Correo = models.EmailField(max_length=255, unique=True)
    IdRol = models.ForeignKey('Roles', on_delete=models.CASCADE, db_column='IdRol', null=True, blank=True)

    class Meta:
        db_table = 'domiciliario'

class producto(models.Model):
    IdProducto = models.AutoField(primary_key=True)  
    Img = models.ImageField(upload_to='productos/')
    Nombre = models.CharField(max_length=100)
    Descripcion = models.CharField(max_length=255)
    Cantidad = models.IntegerField()
    Precio = models.FloatField()
    IdSubCategoria = models.ForeignKey('subcategoria', on_delete=models.CASCADE, db_column='IdSubCategoria')

    class Meta:
        db_table = 'productos'


class Calificacion(models.Model):
    IdCalificacion = models.AutoField(primary_key=True)
    Calificacion = models.IntegerField()
    IdProducto = models.ForeignKey('producto', on_delete=models.CASCADE, db_column='IdProducto')
    IdUsuario = models.ForeignKey('usuario', on_delete=models.CASCADE, db_column='IdUsuario', null=True, blank=True)  # 👈 permitir nulos temporalmente

    class Meta:
        db_table = 'calificacion'
        unique_together = ('IdProducto','IdUsuario')

    def __str__(self):
        return f"{self.IdProducto.Nombre} - {self.Calificacion} estrellas"

class CodigoVerificacion(models.Model):
    usuario = models.ForeignKey(usuario, on_delete=models.CASCADE)
    codigo = models.CharField(max_length=6)
    fecha_creacion = models.DateTimeField(auto_now_add=True)
    fecha_expiracion = models.DateTimeField()
    utilizado = models.BooleanField(default=False)

    def __str__(self):
        return f"Código para {self.usuario.Correo}"
    
    @classmethod
    def generar_codigo(cls, usuario_obj):
        if not isinstance(usuario_obj, usuario):
            raise ValueError("El parámetro 'usuario' debe ser una instancia del modelo usuario.")

        # Invalidar anteriores
        cls.objects.filter(usuario=usuario_obj, utilizado=False).update(utilizado=True)

        codigo = ''.join(random.choices(string.digits, k=6))
        
        # Usar timezone.now() para la expiración
        fecha_expiracion = timezone.now() + timedelta(minutes=15)

        nuevo_codigo = cls.objects.create(
            usuario=usuario_obj,  # 👈 Este es el fix
            codigo=codigo,
            fecha_expiracion=fecha_expiracion
        )

        return nuevo_codigo

    def es_valido(self):
        return not self.utilizado and timezone.now() < self.fecha_expiracion

    
class Notificacion(models.Model):
    titulo = models.CharField(max_length=255)
    mensaje = models.TextField()
    leida = models.BooleanField(default=False)
    fecha = models.DateTimeField(auto_now_add=True)
    administrador = models.ForeignKey('usuario', on_delete=models.CASCADE, db_column='IdUsuario')

    class Meta:
        db_table = 'notificacion'

    def __str__(self):
        return f"{self.titulo} ({'Leída' if self.leida else 'No leída'})"
    

class CarritoCompras(models.Model):
    Id = models.AutoField(primary_key=True)
    CodigoPedido = models.CharField(max_length=50)
    UsuarioId = models.ForeignKey(
        usuario,
        on_delete=models.SET_NULL,
        null=True,
        db_column='UsuarioId'
    )
    ProductoId = models.ForeignKey(
        producto,
        on_delete=models.CASCADE,
        db_column='ProductoId'
    )
    Cantidad = models.PositiveIntegerField()
    PrecioUnitario = models.DecimalField(max_digits=10, decimal_places=2)
    FechaCompra = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'carritocompras'

    def __str__(self):
        return f"{self.Cantidad} x {self.ProductoId}"


class HistorialPedido(models.Model):
    Id = models.AutoField(primary_key=True)
    CodigoPedido = models.CharField(max_length=50, unique=True)
    UsuarioId = models.ForeignKey(
        usuario,
        on_delete=models.SET_NULL,
        null=True,
        db_column='UsuarioId'
    )
    Fecha = models.DateTimeField(auto_now_add=True)
    Total = models.DecimalField(max_digits=10, decimal_places=2)
    Estado = models.CharField(max_length=20, default='pendiente')

    class Meta:
        db_table = 'historial_pedidos'

    def __str__(self):
        return f"Pedido {self.CodigoPedido}"
    
    def productos_json(self):
        detalles = self.detalles.select_related('ProductoId')  # usa el related_name 'detalles'
        productos_list = [
            {"id": detalle.ProductoId.id, "nombre": detalle.ProductoId.Nombre}
            for detalle in detalles if detalle.ProductoId is not None
        ]
        return json.dumps(productos_list, cls=DjangoJSONEncoder)


class HistorialPedido(models.Model):
    Id = models.AutoField(primary_key=True)
    CodigoPedido = models.CharField(max_length=50, unique=True)
    UsuarioId = models.ForeignKey(
        usuario,
        on_delete=models.SET_NULL,
        null=True,
        db_column='UsuarioId'
    )
    Fecha = models.DateTimeField(auto_now_add=True)
    Total = models.DecimalField(max_digits=10, decimal_places=2)
    Estado = models.CharField(max_length=20, default='pendiente')

    Nombre = models.CharField(max_length=150, blank=True, null=True)
    Direccion = models.CharField(max_length=255, blank=True, null=True)
    Correo = models.EmailField(blank=True, null=True)
    Telefono = models.CharField(max_length=20, blank=True, null=True)
    FechaEntrega = models.DateField(blank=True, null=True)

    class Meta:
        db_table = 'historial_pedidos'


class HistorialPedidoDetalle(models.Model):
    Id = models.AutoField(primary_key=True)
    HistorialId = models.ForeignKey(
        HistorialPedido,
        on_delete=models.CASCADE,
        related_name='detalles',
        db_column='HistorialId'
    )
    ProductoId = models.ForeignKey(
        producto,
        on_delete=models.SET_NULL,
        null=True,
        db_column='ProductoId'
    )
    Cantidad = models.PositiveIntegerField()
    PrecioUnitario = models.DecimalField(max_digits=10, decimal_places=2)

    class Meta:
        db_table = 'historial_pedidos_detalle'

    def __str__(self):
        return f"{self.Cantidad} x {self.ProductoId}"
    








    



   