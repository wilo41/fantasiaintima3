from django.shortcuts import render, redirect, get_object_or_404
from django.db import connection
from .models import categoria, subcategoria, roles, usuario, domiciliario, producto, Calificacion
from django.contrib.auth.hashers import make_password, check_password
from django.http import JsonResponse
from django.db.models import Q
from django.contrib import messages
from django.core.mail import send_mail
from django.utils import timezone
from .models import usuario, CodigoVerificacion
from django.db.models import Avg
from django.views.decorators.csrf import csrf_exempt
from django.db import IntegrityError
import re
import json
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.core.paginator import Paginator
from django.urls import reverse
from datetime import datetime, timedelta
from datetime import datetime, timedelta
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.contrib.auth.hashers import check_password
from datetime import datetime, timedelta
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.contrib.auth.hashers import check_password
from .models import Notificacion
from django.contrib.auth.decorators import login_required
from paypal.standard.forms import PayPalPaymentsForm
from django.db.models import Sum, Max, Q
from django.conf import settings
from decimal import Decimal
from django.contrib.auth.models import User
from .models import HistorialPedido, HistorialPedidoDetalle
from django.db import transaction
from django.core.files.storage import FileSystemStorage
from django.core.files.storage import default_storage
from django.utils import timezone
from django.http import HttpResponseBadRequest
from django.contrib import messages
from django.contrib.auth.hashers import make_password
from django.shortcuts import redirect, render
from django.views.decorators.csrf import csrf_exempt
import json
import logging
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from django.db import transaction
from django.urls import reverse

#region landing page
def LadingPage(request):
    categorias = categoria.objects.all().prefetch_related('subcategoria_set')
    productos = producto.objects.all().select_related('IdSubCategoria__categoria').order_by('-IdProducto')

    def agrupar_productos(productos, grupo_de):
        return [productos[i:i+grupo_de] for i in range(0, len(productos), grupo_de)]

    productos_agrupados = agrupar_productos(list(productos), 4)

    return render(request, 'LadingPage.html', {
        'categorias': categorias,
        'productos_agrupados': productos_agrupados,
        'productos': productos, 
        'username': request.session.get('username', ''),
        'first_name': request.session.get('first_name', ''),
    })
#endregion

#region categorias
def validar_nombre_categoria(nombre):
    nombre = nombre.strip()
    if not nombre:
        return False, "El nombre no puede estar vacío."
    if len(nombre) > 80:
        return False, "Nombre demasiado largo. Máximo 80 caracteres."
    if not re.match(r"^[\w\sáéíóúÁÉÍÓÚñÑ-]+$", nombre):
        return False, "El nombre contiene caracteres inválidos."
    return True, None

def insertarcategorias(request):
    if request.method == "POST":
        if request.POST.get('NombreCategoria'):
            nombre = request.POST.get('NombreCategoria').strip()

            valido, error = validar_nombre_categoria(nombre)
            if not valido:
                messages.error(request, error)
                return redirect("listadocategorias")
            
              # limite de 7 categorias
            if categoria.objects.count() >= 7:
                messages.error(request, "No se pueden registrar más de 7 categorías.")
                return redirect("listadocategorias")

            # Comprobar duplicados usando Django ORM
            if categoria.objects.filter(NombreCategoria__iexact=nombre).exists():
                messages.error(request, "La categoría ya existe.")
                return redirect("listadocategorias")

            # Crear la nueva categoría
            categoria.objects.create(NombreCategoria=nombre)
            messages.success(request, "Categoría registrada exitosamente.")
            return redirect("listadocategorias")

    return render(request, 'listadocategorias')

def listadocategorias(request):
    listado = connection.cursor()
    listado.execute("CALL listadocategorias()")
    categorias = listado.fetchall()
    # Ordenar por ID (índice 0) en orden descendente
    categorias = sorted(categorias, key=lambda x: x[0], reverse=True)
    page_number = request.GET.get('page', 1)
    paginator = Paginator(categorias, 5) 
    page_obj = paginator.get_page(page_number)
    return render(request, "crud/categorias.html", {"page_obj": page_obj})

def borrarcategoria(request, id_categoria):
    page = request.GET.get('page', 1)
    try:
        borrar = connection.cursor()
        borrar.execute("CALL borrarcategoria(%s)", [id_categoria])
        messages.success(request, "Categoría eliminada correctamente.")
    except IntegrityError:
        messages.error(request, "No se puede eliminar la categoría porque tiene subcategorías asociadas.")
    return redirect(f'{reverse("listadocategorias")}?page={page}')    

def actualizarcategoria(request, id_categoria):
    page = request.GET.get('page', 1)
    if request.method == "POST":
        if request.POST.get('NombreCategoria'):
            actualizar = connection.cursor()
            actualizar.execute("CALL actualizarcategoria(%s, %s)", [id_categoria, request.POST.get('NombreCategoria')])
            return redirect(f'{reverse("listadocategorias")}?page={page}')
    else:
        categoria = connection.cursor()
        categoria.execute("CALL consultarcategoria(%s)", [id_categoria])
        categoria = categoria.fetchone()
        return render(request, 'crud/editar_categoria.html', {'categoria': categoria})
    
def crudCategorias(request):
    return render(request, 'crud/categorias.html')
# endregion


# region subcategorias
def listadosubcategorias(request):
    subcategorias_list = subcategoria.objects.all().order_by('-IdSubCategoria')
    categorias = categoria.objects.all()
    page_number = request.GET.get('page', 1)
    paginator = Paginator(subcategorias_list, 5)
    page_obj = paginator.get_page(page_number)
    return render(request, 'crud/subcategorias.html', {
        'page_obj': page_obj,
        'categorias': categorias
    })

def validar_nombre_subcategoria(nombre):
    if not nombre or not nombre.strip():
        return "Nombre requerido"
    if re.search(r'[^a-zA-ZáéíóúÁÉÍÓÚñÑüÜ0-9\s]', nombre):
        return "Nombre inválido"
    return None

def insertarsubcategoria(request):
    if request.method == "POST":
        nombre = request.POST.get('nombre', '').strip()
        categoria_id = request.POST.get('categoria_id')
        error = validar_nombre_subcategoria(nombre)
        if error:
            messages.error(request, error)
            return redirect('listadosubcategorias')  # <--- aquí
        # Duplicado
        if subcategoria.objects.filter(NombresubCategoria__iexact=nombre, categoria_id=categoria_id).exists():
            messages.error(request, "Subcategoría ya existe")
            return redirect('listadosubcategorias')  # <--- aquí
        nueva_subcategoria = subcategoria(NombresubCategoria=nombre, categoria_id=categoria_id)
        nueva_subcategoria.save()
        messages.success(request, "Subcategoría registrada exitosamente")
        return redirect('listadosubcategorias')  # <--- aquí
    return redirect('listadosubcategorias')  # <--- aquí

def actualizarsubcategoria(request, id_subcategoria):
    page = request.GET.get('page', 1)
    subcat = get_object_or_404(subcategoria, IdSubCategoria=id_subcategoria)
    if request.method == "POST":
        nombre = request.POST.get('nombre', '').strip()
        categoria_id = request.POST.get('categoria_id')
        error = validar_nombre_subcategoria(nombre)
        if error:
            messages.error(request, error)
            return redirect(f'{reverse("crudSubCategorias")}?page={page}')
        # Sin cambios
        if nombre == subcat.NombresubCategoria and int(categoria_id) == subcat.categoria_id:
            messages.info(request, "Sin cambios realizados")
            return redirect(f'{reverse("listadosubcategorias")}?page={page}')
        # Duplicado
        if subcategoria.objects.filter(NombresubCategoria__iexact=nombre, categoria_id=categoria_id).exclude(IdSubCategoria=id_subcategoria).exists():
            messages.error(request, "Subcategoría ya existe")
            return redirect(f'{reverse("crudSubCategorias")}?page={page}')
        subcat.NombresubCategoria = nombre
        subcat.categoria_id = categoria_id
        subcat.save()
        messages.success(request, "Subcategoría actualizada exitosamente")
        return redirect(f'{reverse("listadosubcategorias")}?page={page}')
    return redirect('crudSubCategorias')

def borrarsubcategoria(request, id_subcategoria):
    page = request.GET.get('page', 1)
    subcat = get_object_or_404(subcategoria, IdSubCategoria=id_subcategoria)
    # Bloquear si tiene productos relacionados
    if producto.objects.filter(IdSubCategoria=subcat).exists():
        messages.error(request, "Subcategoría en uso")
        return redirect(f'{reverse("listadosubcategorias")}?page={page}')
    subcat.delete()
    messages.success(request, "Subcategoría eliminada")
    return redirect(f'{reverse("listadosubcategorias")}?page={page}')


def crudSubCategorias(request):
    subcategorias = subcategoria.objects.all()
    categorias = categoria.objects.all()
    return render(request, 'crud/subcategorias.html', {'subcategorias': subcategorias, 'categorias': categorias})
#endregion


# region login
def validar_registro_usuario(data):
    campos_obligatorios = [
        'PrimerNombre',
        'PrimerApellido',
        'SegundoApellido',
        'Correo',
        'NombreUsuario',
        'Contrasena',
    ]

    # Verificar campos vacíos
    for campo in campos_obligatorios:
        valor = data.get(campo, '').strip()
        if not valor:
            return f"El campo '{campo}' es obligatorio y no puede estar vacío."

    # Validar formato de correo (opcional)
    correo = data.get('Correo', '').strip()
    if '@' not in correo or '.' not in correo:
        return "El correo ingresado no es válido."

    # Verificar que el correo no exista ya (único)
    if usuario.objects.filter(Correo=correo).exists():
        return "Ya existe un usuario registrado con ese correo."
    
    # Validar contraseña
    contrasena = data.get('Contrasena', '')
    
    if len(contrasena) < 8:
        return "La contraseña debe tener como máximo 8 caracteres."

    if ' ' in contrasena:
        return "La contraseña no debe contener espacios."

    if not re.search(r'[^A-Za-z0-9]', contrasena):
        return "La contraseña debe contener al menos un carácter especial."

    return None  # Todo está bien


def registro(request):
    if request.method == "POST":
        data = request.POST
        error = validar_registro_usuario(data)
        if error:
            messages.error(request, error)
            return render(request, 'login/registro.html', {
                'valores': data  # Esto permite mantener los campos ya ingresados
            })

        # Usuario duplicado (case sensitive permitido)
        nombre_usuario = request.POST.get('NombreUsuario').strip()
        if usuario.objects.filter(NombreUsuario=nombre_usuario).exists():
            messages.error(request, "El usuario ya existe")
            return render(request, 'login/registro.html')

        rol_default = roles.objects.get(IdRol=3)
        nuevo_usuario = usuario(
            PrimerNombre=request.POST.get('PrimerNombre').strip(),
            OtrosNombres=request.POST.get('OtrosNombres').strip(),
            PrimerApellido=request.POST.get('PrimerApellido').strip(),
            SegundoApellido=request.POST.get('SegundoApellido').strip(),
            Correo=request.POST.get('Correo').strip(),
            NombreUsuario=nombre_usuario,
            Contrasena=make_password(request.POST.get('Contrasena')),
            idRol=rol_default
        )
        nuevo_usuario.save()
        messages.success(request, "Usuario registrado exitosamente")
        return redirect('login')
    return render(request, 'login/registro.html') 


def login(request):
    max_intentos = 3
    intentos = request.session.get('login_intentos', 0)
    bloqueado = request.session.get('login_bloqueado', False)
    bloqueado_hasta = request.session.get('bloqueado_hasta')

    # --- Validar si el bloqueo sigue vigente ---
    if bloqueado and bloqueado_hasta:
        desbloqueo = datetime.fromisoformat(bloqueado_hasta)
        ahora = datetime.now()
        if ahora < desbloqueo:
            tiempo_restante = int((desbloqueo - ahora).total_seconds())
            return render(request, 'login/login.html', {
                'error': 'Cuenta bloqueada temporalmente. Intenta más tarde.',
                'bloqueado': True,
                'tiempo_restante': tiempo_restante
            })
        else:
            # Se levanta el bloqueo al pasar el tiempo
            request.session['login_bloqueado'] = False
            request.session['bloqueado_hasta'] = None
            request.session['login_intentos'] = 0

    if request.method == "POST":
        correo = request.POST.get('correo', '').strip()
        contrasena = request.POST.get('contrasena', '').strip()

        # --- Validación de campos vacíos ---
        if not correo and not contrasena:
            return render(request, 'login/login.html', {'error': 'Campos obligatorios'})
        if not correo:
            return render(request, 'login/login.html', {'error': 'El correo es obligatorio'})
        if not contrasena:
            return render(request, 'login/login.html', {'error': 'La contraseña es obligatoria'})

        # --- Validación de formato de correo ---
        try:
            validate_email(correo)
        except ValidationError:
            return render(request, 'login/login.html', {'error': 'Credenciales inválidas'})

        # --- Usuario no registrado ---
        try:
            user = usuario.objects.get(Correo=correo)
        except usuario.DoesNotExist:
            return render(request, 'login/login.html', {'error': 'Usuario no encontrado'})
        


        # --- Contraseña incorrecta ---
        if not (user.Contrasena == contrasena or check_password(contrasena, user.Contrasena)):
            intentos += 1
            request.session['login_intentos'] = intentos
            if intentos >= max_intentos:
                request.session['login_bloqueado'] = True
                request.session['bloqueado_hasta'] = (datetime.now() + timedelta(minutes=1)).isoformat()
                return render(request, 'login/login.html', {
                    'error': 'Cuenta bloqueada temporalmente por intentos fallidos',
                    'bloqueado': True,
                    'tiempo_restante': 60
                })
            return render(request, 'login/login.html', {'error': 'Credenciales inválidas'})

        # --- Login exitoso ---
        request.session['user_id'] = user.IdUsuario
        request.session['username'] = user.NombreUsuario
        request.session['nombre'] = f"{user.PrimerNombre} {user.PrimerApellido}"
        request.session['role'] = user.idRol.IdRol
        request.session['login_intentos'] = 0
        request.session['login_bloqueado'] = False
        request.session['bloqueado_hasta'] = None
        return redirect('Ladingpage')

    return render(request, 'login/login.html')


def logout(request):
    request.session.flush()
    return redirect('Ladingpage')  
# endregion


#region contrasena
import threading
import logging
from django.core.mail import EmailMessage
from django.conf import settings
from django.shortcuts import render, redirect
from django.contrib import messages
# importa tus modelos y utilidades
# from .models import usuario, CodigoVerificacion
# from django.contrib.auth.hashers import make_password, check_password
# from django.core.validators import validate_email
# from django.core.exceptions import ValidationError

logger = logging.getLogger(__name__)

def _enviar_email_async(asunto, mensaje_html, from_email, destinatario):
    """Enviar correo en background para no bloquear la request HTTP."""
    try:
        msg = EmailMessage(
            asunto,
            mensaje_html,
            from_email,
            [destinatario],
        )
        msg.content_subtype = "html"
        msg.send(fail_silently=False)
        logger.info("Correo de recuperación enviado a %s", destinatario)
    except Exception as e:
        logger.exception("Error enviando correo de recuperación a %s: %s", destinatario, e)


def solicitar_recuperacion(request):
    """
    Vista para solicitar código de recuperación.
    El envío del correo se hace en un hilo para evitar timeouts del worker.
    """
    if request.method == 'POST':
        email = (request.POST.get('email') or '').strip()
        logger.info("Solicitud de recuperación iniciada para email=%s", email)

        if not email:
            messages.error(request, "Debes ingresar un correo.")
            return render(request, 'login/recuperarcontraseña.html')

        # Validación rápida del formato del email (no imprescindible)
        try:
            validate_email(email)
        except Exception:
            messages.error(request, "El correo ingresado no tiene un formato válido.")
            return render(request, 'login/recuperarcontraseña.html')

        # Buscar usuario
        try:
            user = usuario.objects.get(Correo=email)
        except usuario.DoesNotExist:
            logger.info("Email no encontrado en DB: %s", email)
            messages.error(request, 'No existe una cuenta asociada a ese correo.')
            return render(request, 'login/recuperarcontraseña.html')

        # Generar código (asegúrate de que este método no haga llamadas lentas)
        try:
            logger.debug("Generando CodigoVerificacion para user id=%s", user.IdUsuario)
            codigo_obj = CodigoVerificacion.generar_codigo(user)
            logger.debug("Codigo generado: %s", getattr(codigo_obj, 'codigo', None))
        except Exception:
            logger.exception("Error al generar código para %s", email)
            messages.error(request, 'Ocurrió un error interno. Intenta de nuevo más tarde.')
            return render(request, 'login/recuperarcontraseña.html')

        # Preparar HTML del correo (mantén tu plantilla HTML)
        mensaje_html = f"""
        <html>
          <head>
            <style>/* tu CSS... */</style>
          </head>
          <body>
            <div class="container">
              <h2 class="header">Recuperación de Contraseña</h2>
              <p>Hola,</p>
              <p>Recibimos una solicitud para recuperar el acceso a tu cuenta en <strong>Fantasía Íntima</strong>.</p>
              <p>Ingresa el siguiente código en la página para continuar con el proceso:</p>
              <div class="codigo">{codigo_obj.codigo}</div>
              <p>Este código estará disponible durante los próximos <strong>15 minutos</strong>.</p>
            </div>
          </body>
        </html>
        """

        # Lanzar envío en background (hilo daemon)
        try:
            t = threading.Thread(
                target=_enviar_email_async,
                args=( 'Código de recuperación de contraseña', mensaje_html, settings.DEFAULT_FROM_EMAIL, email),
                daemon=True
            )
            t.start()
            logger.info("Hilo de envío iniciado para %s", email)
        except Exception:
            logger.exception("No se pudo iniciar hilo de envío para %s", email)
            messages.warning(request, 'Hubo un problema al enviar el correo. Intenta más tarde.')

        # Guardar en sesión y redirigir inmediatamente
        request.session['email_recuperacion'] = email
        messages.success(request, 'Se ha enviado un código de verificación a tu correo (revisa spam).')
        return redirect('verificar_codigo')

    return render(request, 'login/recuperarcontraseña.html')



def verificar_codigo(request):
    email = request.session.get('email_recuperacion')
    
    if not email:
        messages.error(request, 'Debes solicitar un código primero.')
        return redirect('solicitar_recuperacion')
    
    if request.method == 'POST':
        codigo_ingresado = ''.join([request.POST.get(f'digit{i}', '') for i in range(1, 7)])
        
        try:
            user = usuario.objects.get(Correo=email)
            codigo_obj = CodigoVerificacion.objects.filter(
                usuario=user,
                utilizado=False,
                codigo=codigo_ingresado
            ).latest('fecha_creacion')
            
            if codigo_obj.es_valido():
                codigo_obj.utilizado = True
                codigo_obj.save()
                
                request.session['codigo_verificado'] = True
                return redirect('nueva_contrasena')
            else:
                messages.error(request, 'El código ha expirado.')
        
        except (usuario.DoesNotExist, CodigoVerificacion.DoesNotExist):
            messages.error(request, 'Código inválido.')
    
    return render(request, 'login/codigo.html')

def nueva_contrasena(request):
    email = request.session.get('email_recuperacion')
    codigo_verificado = request.session.get('codigo_verificado', False)
    
    if not email or not codigo_verificado:
        messages.error(request, 'Debes verificar un código primero.')
        return redirect('solicitar_recuperacion')
    
    if request.method == 'POST':
        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        
        if password != password2:
            messages.error(request, 'Las contraseñas no coinciden.')
            return render(request, 'nueva_contrasena.html')
        
        try:
            user = usuario.objects.get(Correo=email)
            user.Contrasena = make_password(password)  # Importante: hashear la nueva contraseña
            user.save()
            
            # Limpiar la sesión
            request.session.pop('email_recuperacion', None)
            request.session.pop('codigo_verificado', None)
            
            return redirect('login')
        
        except usuario.DoesNotExist:
            messages.error(request, 'Ocurrió un error al actualizar la contraseña.')
    
    return render(request, 'login/nuevaContraseña.html')

def recuperarContraseña(request):
    return render(request, 'login/recuperarcontraseña.html')

def codigo(request):
    return render(request, 'login/codigo.html')

def nuevaContraseña(request):
    return render(request, 'login/nuevaContraseña.html')

#endregion

#region usuarios
def insertarusuario(request):
    if request.method == "POST":
        # Validar que todos los campos requeridos estén presentes
        campos = ['PrimerNombre', 'OtrosNombres', 'PrimerApellido', 'SegundoApellido', 'Correo', 'NombreUsuario', 'Contrasena']
        if all(request.POST.get(campo) for campo in campos):
            correo = request.POST.get('Correo')
            nombre_usuario = request.POST.get('NombreUsuario')

            # Validar si el correo ya está registrado
            if usuario.objects.filter(Correo=correo).exists():
                messages.error(request, 'El correo ya está registrado en el sistema.')
                return redirect('crudUsuarios')

            # Validar si el nombre de usuario ya está registrado
            if usuario.objects.filter(NombreUsuario=nombre_usuario).exists():
                messages.error(request, 'El nombre de usuario ya está registrado en el sistema.')
                return redirect('crudUsuarios')

            try:
                rol_default = roles.objects.get(IdRol=2)  # Rol por defecto: cliente
                nuevo_usuario = usuario(
                    PrimerNombre=request.POST.get('PrimerNombre'),
                    OtrosNombres=request.POST.get('OtrosNombres'),
                    PrimerApellido=request.POST.get('PrimerApellido'),
                    SegundoApellido=request.POST.get('SegundoApellido'),
                    Correo=correo,
                    NombreUsuario=nombre_usuario,
                    Contrasena=make_password(request.POST.get('Contrasena')),
                    idRol=rol_default
                )
                nuevo_usuario.save()
                messages.success(request, 'Usuario registrado exitosamente.')
                return redirect('crudUsuarios')

            except roles.DoesNotExist:
                messages.error(request, 'El rol especificado no existe.')
                return redirect('crudUsuarios')
        else:
            messages.error(request, 'Todos los campos son obligatorios.')
            return redirect('crudUsuarios')

    return redirect('crudUsuarios')

def editarusuario(request, id_usuario):
    page = request.GET.get('page', 1)
    usuario_obj = usuario.objects.get(IdUsuario=id_usuario)
    if request.method == "POST":
        usuario_obj.PrimerNombre = request.POST.get('PrimerNombre')
        usuario_obj.OtrosNombres = request.POST.get('OtrosNombres')
        usuario_obj.PrimerApellido = request.POST.get('PrimerApellido')
        usuario_obj.SegundoApellido = request.POST.get('SegundoApellido')
        usuario_obj.Correo = request.POST.get('Correo')
        usuario_obj.NombreUsuario = request.POST.get('NombreUsuario')
        if request.POST.get('Contrasena'):
            usuario_obj.Contrasena = make_password(request.POST.get('Contrasena'))
        usuario_obj.save()
        return redirect(f'{reverse("crudUsuarios")}?page={page}')
    return render(request, 'crud/editar_usuario.html', {'usuario': usuario_obj})

def borrarusuario(request, id_usuario):
    page = request.GET.get('page', 1)
    usuario_obj = usuario.objects.get(IdUsuario=id_usuario)
    usuario_obj.delete()
    return redirect(f'{reverse("crudUsuarios")}?page={page}')

def crudUsuarios(request):
    usuarios_list = usuario.objects.filter(idRol=2).order_by('-IdUsuario')
    page_number = request.GET.get('page', 1)
    paginator = Paginator(usuarios_list, 5)
    page_obj = paginator.get_page(page_number)
    return render(request, 'crud/usuarios.html', {'page_obj': page_obj})
#endregion


#region domiciliario
def insertardomiciliario(request):
    if request.method == "POST":
        try:
            rol_domiciliario = roles.objects.get(IdRol=3)

            tipo_doc = request.POST.get('TipoDocumento')
            documento = request.POST.get('Documento')
            correo = request.POST.get('Correo')

            if domiciliario.objects.filter(Documento=documento).exists():
                messages.error(request, 'El documento ya está registrado en el sistema.')
                return redirect('crudDomiciliarios')

            if domiciliario.objects.filter(Correo=correo).exists():
                messages.error(request, 'El correo electrónico ya está registrado en el sistema.')
                return redirect('crudDomiciliarios')

            nuevo_domiciliario = domiciliario(
                TipoDocumento=tipo_doc,
                Documento=documento,
                NombreDomiciliario=request.POST.get('NombreDomiciliario'),
                PrimerApellido=request.POST.get('PrimerApellido'),
                SegundoApellido=request.POST.get('SegundoApellido'),
                Celular=request.POST.get('Celular'),
                Ciudad=request.POST.get('Ciudad'),
                Correo=correo,
                IdRol=rol_domiciliario
            )

            nuevo_domiciliario.save()
            messages.success(request, 'Domiciliario registrado exitosamente.')
            return redirect('crudDomiciliarios')

        except roles.DoesNotExist:
            messages.error(request, 'El rol especificado no existe en el sistema.')
            return redirect('crudDomiciliarios')

    return redirect('crudDomiciliarios')

def editardomiciliario(request, id_domiciliario):
    page = request.GET.get('page', 1)
    domiciliario_obj = get_object_or_404(domiciliario, IdDomiciliario=id_domiciliario)
    
    if request.method == "POST":
        domiciliario_obj.TipoDocumento = request.POST.get('TipoDocumento')
        domiciliario_obj.Documento = request.POST.get('Documento')
        domiciliario_obj.NombreDomiciliario = request.POST.get('NombreDomiciliario')
        domiciliario_obj.PrimerApellido = request.POST.get('PrimerApellido')
        domiciliario_obj.SegundoApellido = request.POST.get('SegundoApellido')
        domiciliario_obj.Celular = request.POST.get('Celular')
        domiciliario_obj.Ciudad = request.POST.get('Ciudad')
        domiciliario_obj.Correo = request.POST.get('Correo')
    
        domiciliario_obj.save()
        return redirect(f'{reverse("crudDomiciliarios")}?page={page}')
    
    return render(request, 'crud/editar_domiciliario.html', {'domiciliario': domiciliario_obj})

def borrardomiciliario(request, id_domiciliario):
    page = request.GET.get('page', 1)
    domiciliario_obj = domiciliario.objects.get(IdDomiciliario=id_domiciliario)
    domiciliario_obj.delete()
    return redirect(f'{reverse("crudDomiciliarios")}?page={page}')


def crudDomiciliarios(request):
    domiciliarios_list = domiciliario.objects.filter(IdRol=3).order_by('-IdDomiciliario')
    page_number = request.GET.get('page', 1)
    paginator = Paginator(domiciliarios_list, 5)
    page_obj = paginator.get_page(page_number)
    return render(request, 'crud/domiciliarios.html', {'page_obj': page_obj})
#endregion


#region productos
def validar_nombre_producto(nombre):
    if not nombre or not nombre.strip():
        return "El nombre es obligatorio."
    if re.search(r'[^a-zA-ZáéíóúÁÉÍÓÚñÑüÜ0-9\s]', nombre):
        return "Nombre inválido: no se permiten caracteres especiales."
    return None

def insertarproducto(request):
    if request.method == "POST":
        nombre = request.POST.get('Nombre', '').strip()
        descripcion = request.POST.get('Descripcion', '').strip()
        precio = request.POST.get('Precio')
        cantidad = request.POST.get('Cantidad')
        id_subcategoria = request.POST.get('IdSubCategoria')
        img = request.FILES.get('Img')

        # Validaciones
        error = validar_nombre_producto(nombre)
        if error:
            messages.error(request, error)
            return redirect('crudProductos')
        if not id_subcategoria:
            messages.error(request, "La subcategoría es obligatoria.")
            return redirect('crudProductos')
        # Duplicado: mismo nombre y subcategoría
        if producto.objects.filter(Nombre__iexact=nombre, IdSubCategoria_id=id_subcategoria).exists():
            messages.error(request, "Ya existe un producto con ese nombre en la misma subcategoría.")
            return redirect('crudProductos')

        # Crear producto
        nuevo_producto = producto(
            Nombre=nombre,
            Descripcion=descripcion,
            Precio=precio,
            Cantidad=cantidad,
            IdSubCategoria=subcategoria.objects.get(IdSubCategoria=id_subcategoria),
            Img=img
        )
        nuevo_producto.save()
        messages.success(request, "Producto registrado exitosamente")
        return redirect('crudProductos')
    return render(request, 'crud/productos.html')

def editarproducto(request, id_producto):
    page = request.GET.get('page', 1)
    producto_obj = get_object_or_404(producto, IdProducto=id_producto)
    if request.method == "POST":
        nombre = request.POST.get('Nombre', '').strip()
        descripcion = request.POST.get('Descripcion', '').strip()
        precio = request.POST.get('Precio')
        cantidad = request.POST.get('Cantidad')
        id_subcategoria = request.POST.get('IdSubCategoria')
        img = request.FILES.get('Img')

        # Validaciones
        error = validar_nombre_producto(nombre)
        if error:
            messages.error(request, error)
            return redirect(f'{reverse("crudProductos")}?page={page}')
        if not id_subcategoria:
            messages.error(request, "La subcategoría es obligatoria.")
            return redirect(f'{reverse("crudProductos")}?page={page}')
        # Duplicado: mismo nombre y subcategoría, excluyendo el actual
        if producto.objects.filter(
            Nombre__iexact=nombre,
            IdSubCategoria_id=id_subcategoria
        ).exclude(IdProducto=id_producto).exists():
            messages.error(request, "Ya existe un producto con ese nombre en la misma subcategoría.")
            return redirect(f'{reverse("crudProductos")}?page={page}')

        # Actualizar producto
        producto_obj.Nombre = nombre
        producto_obj.Descripcion = descripcion
        producto_obj.Precio = precio
        producto_obj.Cantidad = cantidad
        producto_obj.IdSubCategoria = subcategoria.objects.get(IdSubCategoria=id_subcategoria)
        if img:
            producto_obj.Img = img
        producto_obj.save()
        messages.success(request, "Producto modificado exitosamente")
        return redirect(f'{reverse("crudProductos")}?page={page}')
    return render(request, 'crud/editar_producto.html', {'producto': producto_obj})

def borrarproducto(request, id_producto):
    page = request.GET.get('page', 1)
    producto_obj = get_object_or_404(producto, IdProducto=id_producto)
    producto_obj.delete()
    return redirect(f'{reverse("crudProductos")}?page={page}') 

def crudProductos(request):
    productos_list = producto.objects.all().order_by('-IdProducto')
    subcategorias = subcategoria.objects.all()
    page_number = request.GET.get('page', 1)
    paginator = Paginator(productos_list, 5) 
    page_obj = paginator.get_page(page_number)
    return render(request, 'crud/productos.html', {
        'page_obj': page_obj,
        'subcategorias': subcategorias
    })
#endregion

#region calificaciones
@csrf_exempt
def guardar_calificacion(request):
    try:
        if request.method != "POST":
            return JsonResponse({'success': False, 'mensaje': 'Método no permitido'}, status=405)

        import json
        data = json.loads(request.body.decode('utf-8'))

        id_producto = data.get('id_producto')
        calificacion = data.get('calificacion')  # ⚠ debe coincidir con JS

        if not id_producto or not calificacion:
            return JsonResponse({'success': False, 'mensaje': 'Faltan datos'})

        producto_obj = producto.objects.filter(IdProducto=id_producto).first()
        if not producto_obj:
            return JsonResponse({'success': False, 'mensaje': 'Producto no encontrado'})

        # Guardar calificación
        Calificacion.objects.create(
            IdProducto=producto_obj,
            Calificacion=int(calificacion)
        )

        # Calcular promedio
        from django.db.models import Avg
        promedio = Calificacion.objects.filter(IdProducto=producto_obj).aggregate(
            Avg('Calificacion')
        )['Calificacion__avg'] or 0
        total_reviews = Calificacion.objects.filter(IdProducto=producto_obj).count()

        return JsonResponse({
            'success': True,
            'mensaje': 'Gracias por tu calificación',
            'nuevo_promedio': round(promedio, 1),
            'total_reviews': total_reviews
        })

    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'mensaje': 'JSON inválido'})
    except Exception as e:
        print("Error interno:", e)
        return JsonResponse({'success': False, 'mensaje': str(e)})
# endregion

# region perfiles
def perfiles(request):
    if not request.session.get('user_id'):
        return redirect('login')
    
    try:
        user = usuario.objects.get(IdUsuario=request.session['user_id'])
        
        if request.method == 'POST':
            # Verificar si es una actualización de datos o solo de imagen
            if 'profile-pic' in request.FILES:
                # Solo actualizar imagen
                user.imagen_perfil = request.FILES['profile-pic']
                user.save()
                return JsonResponse({
                    'status': 'success',
                    'new_image_url': user.imagen_perfil.url if user.imagen_perfil else '/static/img/perfil.png'
                })
            else:
                # Actualizar datos del perfil
                user.PrimerNombre = request.POST.get('primerNombre', user.PrimerNombre)
                user.OtrosNombres = request.POST.get('segundoNombre', user.OtrosNombres)
                user.PrimerApellido = request.POST.get('primerApellido', user.PrimerApellido)
                user.SegundoApellido = request.POST.get('segundoApellido', user.SegundoApellido)
                user.NombreUsuario = request.POST.get('nombreUsuario', user.NombreUsuario)
                
                if request.POST.get('contrasena'):
                    user.Contraseña = make_password(request.POST.get('contrasena'))
                
                user.save()
                request.session['nombre'] = f"{user.PrimerNombre} {user.PrimerApellido}"
                return redirect('perfiles')
        
        return render(request, 'perfiles.html', {
        'usuario': user,
        'imagen_perfil': user.imagen_perfil.url if user.imagen_perfil else '/static/img/perfil.png'
    })
        
    except usuario.DoesNotExist:
        return redirect('login')

def eliminar_foto_perfil(request):
    if request.method == 'POST' and request.session.get('user_id'):
        try:
            user = usuario.objects.get(IdUsuario=request.session['user_id'])
            if user.imagen_perfil:
                user.imagen_perfil.delete()
                user.imagen_perfil = None
                user.save()
            return JsonResponse({
                'status': 'success',
                'new_image_url': '/static/img/perfil.png'
            })
        except usuario.DoesNotExist:
            pass
    return JsonResponse({'status': 'error'}, status=400)

def eliminar_cuenta(request):
    if request.method == 'POST' and request.session.get('user_id'):
        try:
            user = usuario.objects.get(IdUsuario=request.session['user_id'])
            user.delete()  # Delete the user account
            request.session.flush() 
            return redirect('Ladingpage')  
        except usuario.DoesNotExist:
            pass
    return JsonResponse({'status': 'error'}, status=400)
# endregion

#region filtrar Filtrar productos que pertenecen a la categoría
def lencerias(request):
    categorias = categoria.objects.all()
    productos = producto.objects.filter(
        IdSubCategoria__categoria__NombreCategoria='Lencerías'
    ).order_by('-IdProducto')

    pendientes = 0
    if request.session.get('role') == 1:
        pendientes = Notificacion.objects.filter(leida=False).count()

    return render(request, 'carrito/lencerias.html', {
        'categorias': categorias,
        'productos': productos,
        'pendientes': pendientes,
    })


def vibradores(request):
    categorias = categoria.objects.all()
    productos = producto.objects.filter(
        IdSubCategoria__categoria__NombreCategoria='Vibradores'
    ).order_by('-IdProducto')

    pendientes = 0
    if request.session.get('role') == 1:
        pendientes = Notificacion.objects.filter(leida=False).count()

    return render(request, 'carrito/vibradores.html', {
        'categorias': categorias,
        'productos': productos,
        'pendientes': pendientes,
    })


from django.db.models import Avg, Count

def disfraces(request):
    categorias = categoria.objects.all()
    user_id = request.session.get('user_id')  # Obtener ID del usuario logueado
    
    productos = producto.objects.filter(
        IdSubCategoria__categoria__NombreCategoria='Disfraces'
    ).annotate(
        rating=Avg('calificacion__Calificacion'),  # Promedio de calificaciones (relación inversa)
        review_count=Count('calificacion')  # Conteo de calificaciones
    ).order_by('-IdProducto')
    
    # Asignar user_rating a cada producto (un solo loop, optimizado)
    for prod in productos:  # 👈 Cambiado: 'prod' en lugar de 'producto' para evitar shadowing
        prod.user_rating = 0  # Valor por defecto (vacío/no calificado)
        if user_id:
            try:
                user_calif = Calificacion.objects.get(
                    IdProducto=prod,  # 👈 Usar 'prod'
                    IdUsuario_id=user_id
                )
                prod.user_rating = user_calif.Calificacion  # e.g., 3
            except Calificacion.DoesNotExist:
                prod.user_rating = 0  # No ha calificado
    
    pendientes = 0
    if request.session.get('role') == 1:
        pendientes = Notificacion.objects.filter(leida=False).count()
    
    return render(request, 'carrito/disfraces.html', {
        'categorias': categorias,
        'productos': productos,
        'pendientes': pendientes,
    })


def dildos(request):
    categorias = categoria.objects.all()
    productos = producto.objects.filter(
        IdSubCategoria__categoria__NombreCategoria='Dildos'
    ).order_by('-IdProducto')

    pendientes = 0
    if request.session.get('role') == 1:
        pendientes = Notificacion.objects.filter(leida=False).count()

    return render(request, 'carrito/dildos.html', {
        'categorias': categorias,
        'productos': productos,
        'pendientes': pendientes,  
    })

def productosCarrito(request):
    categorias = categoria.objects.all()
    productos = producto.objects.all().order_by('-IdProducto')
    pendientes = 0
    if request.session.get('role') == 1:
        pendientes = Notificacion.objects.filter(leida=False).count()

   
    usuario_id = request.session.get('user_id')  

    for p in productos:
        promedio = Calificacion.objects.filter(IdProducto=p).aggregate(Avg('Calificacion'))['Calificacion__avg'] or 0
        calificacion_usuario = Calificacion.objects.filter(IdProducto=p, IdUsuario_id=usuario_id).first()
        p.rating = promedio
        p.user_rating = calificacion_usuario.Calificacion if calificacion_usuario else 0

    return render(request, 'carrito/productos.html', {
        'categorias': categorias,
        'productos': productos,
        'pendientes': pendientes,
    })
#endregion

#region notificaciones
def lista_notificaciones(request):
    # Traer todas las notificaciones
    notificaciones = Notificacion.objects.all().order_by('-fecha')
    pendientes = Notificacion.objects.filter(leida=False).count()

    return render(request, 'notificaciones.html', {
        'notificaciones': notificaciones,
        'pendientes': pendientes, 
    })

from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def marcar_leida(request, id_notificacion):
    if request.method == 'POST':
        try:
            notificacion = Notificacion.objects.get(id=id_notificacion)
            notificacion.leida = True
            notificacion.save()

            # Contar notificaciones pendientes
            pendientes = Notificacion.objects.filter(leida=False).count()

            return JsonResponse({'success': True, 'pendientes': pendientes})
        except Notificacion.DoesNotExist:
            return JsonResponse({'success': False, 'mensaje': 'Notificación no encontrada'}, status=404)

    return JsonResponse({'success': False, 'mensaje': 'Método no permitido'}, status=405)
#endregion

#region agregar al carrito
@csrf_exempt
def agregar_al_carrito(request, producto_id):
    if request.method == "POST":
        producto = producto.objects.get(pk=producto_id)
        if producto.Cantidad > 0:
            producto.Cantidad -= 1
            producto.save()

            carrito = request.session.get("carrito", {})
            carrito[str(producto_id)] = carrito.get(str(producto_id), 0) + 1
            request.session["carrito"] = carrito

            total_items = sum(carrito.values())

            return JsonResponse({
                "success": True,
                "total_items": total_items,
                "stock_restante": producto.Cantidad
            })

        return JsonResponse({"success": False, "error": "Sin stock"})
#endregion

#region pasarela de pago
@csrf_exempt
@login_required
def registrar_pago(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            nombre = data.get("nombre")
            direccion = data.get("direccion")
            correo = data.get("correo")
            telefono = data.get("telefono")
            carrito = data.get("carrito", [])
            total = data.get("total")

            fecha_pedido = now().date()
            fecha_entrega = fecha_pedido 

            # Crear historial del pedido
            historial = HistorialPedido.objects.create(
                Cliente=request.user,
                Nombre=nombre,
                Direccion=direccion,
                Correo=correo,
                Telefono=telefono,
                Fecha=fecha_pedido,
                FechaEntrega=fecha_entrega,
                Total=total,
                Estado="En proceso"
            )

            # Guardar detalles y controlar stock
            for item in carrito:
                try:
                    prod = producto.objects.get(pk=item['IdProducto'])
                    
                    # Crear detalle del pedido
                    HistorialPedidoDetalle.objects.create(
                        HistorialId=historial,
                        ProductoId=prod,
                        Cantidad=item['cantidad'],
                        PrecioUnitario=prod.Precio
                    )

                    # Reducir stock
                    prod.Stock -= item['cantidad']
                    prod.save()

                    # Crear notificación si se queda sin stock
                    if prod.Stock <= 0:
                        Notificacion.objects.create(
                            titulo=f"Producto sin stock: {prod.Nombre}",
                            mensaje=f"El producto '{prod.Nombre}' se ha quedado sin stock.",
                            administrador=request.user
                        )

                except producto.DoesNotExist:
                    continue

            # 🔹 Vaciar carrito de la sesión
            request.session['carrito'] = {}
            request.session.modified = True

            return JsonResponse({
                "success": True,
                "mensaje": "✅ Tu compra fue registrada con éxito.",
                "redirect": reverse("pedido")
            })

        except Exception as e:
            return JsonResponse({
                "success": False,
                "mensaje": f"Error al registrar el pago: {str(e)}"
            }, status=500)

    return JsonResponse({
        "success": False,
        "mensaje": "Método no permitido."
    }, status=405)

def pago_paypal(request):
    # Datos básicos de la transacción
    paypal_dict = {
        "business": settings.PAYPAL_RECEIVER_EMAIL,
        "amount": "20.00",
        "item_name": "Compra de prueba",
        "invoice": "INV-0001",
        "currency_code": "USD",
        "notify_url": request.build_absolute_uri(reverse('paypal-ipn')),
        "return_url": request.build_absolute_uri(reverse('pago_exitoso')),
        "cancel_return": request.build_absolute_uri(reverse('pago_cancelado')),
    }

    form = PayPalPaymentsForm(initial=paypal_dict)
    return render(request, "pago.html", {"form": form})

def pago_exitoso(request):
    codigo_pedido = request.session.get('ultimo_pedido_codigo')
    if not codigo_pedido:
        return redirect("pedido")

    try:
        with transaction.atomic():
            pedido = HistorialPedido.objects.get(CodigoPedido=codigo_pedido)
            pedido.Estado = "Solicitado"
            pedido.save()

            # Descontar stock (por si no lo hiciste en pago_paypal_carrito)
            detalles = HistorialPedidoDetalle.objects.filter(HistorialId=pedido)
            for detalle in detalles:
                if detalle.ProductoId.Cantidad >= detalle.Cantidad:
                    detalle.ProductoId.Cantidad -= detalle.Cantidad
                    detalle.ProductoId.save()

        # 🔥 limpiar carrito y el código de pedido de la sesión
        request.session.pop('carrito', None)
        request.session.pop('ultimo_pedido_codigo', None)
        request.session.modified = True

        # Mensaje de confirmación
        messages.success(request, "✅ ¡Tu compra fue registrada con éxito! Puedes ver los detalles en tu historial.")
        return redirect('pedido')

    except HistorialPedido.DoesNotExist:
        return redirect("Ladingpage")

def pago_cancelado(request):
    return redirect('carrito')

@csrf_exempt
def obtener_carrito_usuario(request):
    if request.method == 'GET':
        try:
            carrito_session = request.session.get('carrito', {})
            carrito_list = []
            for prod_id_str, cantidad in carrito_session.items():
                try:
                    prod_id = int(prod_id_str)
                    prod = producto.objects.get(IdProducto=prod_id)
                    carrito_list.append({
                        'IdProducto': prod.IdProducto,
                        'nombre': prod.Nombre,
                        'precio': float(prod.Precio),  
                        'cantidad': int(cantidad),
                    })
                except (ValueError, producto.DoesNotExist):
                    logger.warning(f"Producto {prod_id_str} no encontrado en carrito")
                    continue
            
            logger.info(f"Carrito enviado: {len(carrito_list)} items")
            return JsonResponse({'carrito': carrito_list})
        except Exception as e:
            logger.error(f"Error al obtener carrito: {e}")
            return JsonResponse({'error': str(e)}, status=500)
    return JsonResponse({'error': 'Solo GET permitido'}, status=405)


logger = logging.getLogger(__name__)
@csrf_exempt
def pago_paypal_carrito(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            total = data.get("total")
            carrito = data.get("carrito", [])

            if not carrito or not total:
                return JsonResponse({"error": "Carrito vacío o total no enviado"}, status=400)

            # 🔑 Usuario autenticado
            user_id = request.session.get('user_id')
            usuario_obj = usuario.objects.get(IdUsuario=user_id) if user_id else None

            # ✅ Crear pedido en BD con estado "Pendiente de pago"
            codigo_pedido = f"PP-{datetime.now().strftime('%Y%m%d%H%M%S')}"
            with transaction.atomic():
                pedido = HistorialPedido.objects.create(
                    CodigoPedido=codigo_pedido,
                    UsuarioId=usuario_obj,
                    Total=Decimal(str(total)),
                    Estado='Pendiente de pago',
                    Nombre=data.get('nombre'),
                    Direccion=data.get('direccion'),
                    Correo=data.get('correo'),
                    Telefono=data.get('telefono'),
                    FechaEntrega=data.get('fechaEntrega'),
                )

                for item in carrito:
                    prod_id = item.get('IdProducto')
                    if not prod_id:
                        continue
                    try:
                        prod = producto.objects.get(IdProducto=prod_id)
                        HistorialPedidoDetalle.objects.create(
                            HistorialId=pedido,
                            ProductoId=prod,
                            Cantidad=item.get('cantidad', 1),
                            PrecioUnitario=Decimal(str(item.get('precio', 0)))
                        )
                    except producto.DoesNotExist:
                        continue

            # Guardar el código del pedido en la sesión para recuperarlo en pago_exitoso
            request.session['ultimo_pedido_codigo'] = codigo_pedido
            request.session.modified = True

            # ✅ Generar formulario de PayPal
            paypal_dict = {
                "business": settings.PAYPAL_RECEIVER_EMAIL,
                "amount": f"{float(total):.2f}",
                "item_name": "Compra en Fantasía Íntima",
                "invoice": codigo_pedido,
                "currency_code": "USD",
                "notify_url": request.build_absolute_uri(reverse("paypal-ipn")),
                "return_url": request.build_absolute_uri(reverse("pago_exitoso")),
                "cancel_return": request.build_absolute_uri(reverse("pago_cancelado")),
            }

            form = PayPalPaymentsForm(initial=paypal_dict)
            return JsonResponse({"form_html": form.render()})

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Método no permitido"}, status=405)

from django.utils.timezone import now
#endregion

#region pedidos
@csrf_exempt
def detalles_pedido(request, codigo_pedido):
    if request.method == 'GET':
        try:
            pedido = HistorialPedido.objects.get(CodigoPedido=codigo_pedido)
            detalles = HistorialPedidoDetalle.objects.filter(HistorialId=pedido).select_related('ProductoId')

            datos_pedido = {
                'codigo_pedido': codigo_pedido,
                'cliente': f"{pedido.UsuarioId.PrimerNombre} {pedido.UsuarioId.PrimerApellido}" if pedido.UsuarioId else pedido.Nombre,
                'correo': pedido.Correo,
                'telefono': pedido.Telefono,
                'direccion': pedido.Direccion,
                # ✅ Si existe fecha_entrega, la formateamos, si no, devolvemos un string vacío
                'fecha_entrega': pedido.FechaEntrega.strftime('%Y-%m-%d') if pedido.FechaEntrega else '',
                'fecha': pedido.Fecha.strftime('%Y-%m-%d'),
                'total': float(pedido.Total),
                'articulos': []
            }

            for detalle in detalles:
                datos_pedido['articulos'].append({
                    'nombre': detalle.ProductoId.Nombre,
                    'cantidad': detalle.Cantidad,
                    'precio_unitario': float(detalle.PrecioUnitario),
                    'total': float(detalle.PrecioUnitario * detalle.Cantidad),
                    'imagen': detalle.ProductoId.Img.url if detalle.ProductoId and detalle.ProductoId.Img else ''
                })

            return JsonResponse(datos_pedido)
        except HistorialPedido.DoesNotExist:
            return JsonResponse({'error': 'Pedido no encontrado'}, status=404)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Método no permitido'}, status=405)


def pedido(request):
    user_id = request.session.get('user_id')
    role = request.session.get('role')
    if not user_id:
        return redirect('login')

    if role == 1:
        pedidos_qs = HistorialPedido.objects.all().order_by('-Fecha')
    else:
        pedidos_qs = HistorialPedido.objects.filter(UsuarioId=user_id).order_by('-Fecha')

    pedidos = []
    for p in pedidos_qs:
        detalles = HistorialPedidoDetalle.objects.filter(HistorialId=p.Id).select_related('ProductoId')
        pedidos.append({
            'codigo_pedido': p.CodigoPedido,
            'cliente': f"{p.UsuarioId.PrimerNombre} {p.UsuarioId.PrimerApellido}" if p.UsuarioId else p.Nombre,
            'correo': p.Correo,
            'telefono': p.Telefono,
            'direccion': p.Direccion,
            'fecha_entrega': p.FechaEntrega,
            'items': detalles,
            'total': "{:,.2f}".format(p.Total).replace(',', 'X').replace('.', ',').replace('X', '.'),
            'fecha': p.Fecha,
            'estado': p.Estado,
        })
    return render(request, 'pedido.html', {'pedidos': pedidos})

def productos_por_pedido_view(request, pedido_id):
    detalles = HistorialPedidoDetalle.objects.filter(HistorialId=pedido_id)
    data = [
        {
            "id": d.Id,
            "nombre": d.ProductoId.Nombre if d.ProductoId else "Producto eliminado",
            "cantidad": d.Cantidad
        }
        for d in detalles
    ]
    return JsonResponse(data, safe=False)

@require_POST
def cancelar_pedido(request, codigo_pedido):
    try:
        pedido = HistorialPedido.objects.get(CodigoPedido=codigo_pedido)
        if pedido.Estado.lower() != 'cancelado':
            pedido.Estado = 'Cancelado'
            pedido.save()
            return JsonResponse({
                'success': True,
                'estado': pedido.Estado,
                'codigo_pedido': pedido.CodigoPedido
            })
        else:
            return JsonResponse({'success': False, 'error': 'El pedido ya estaba cancelado'})
    except HistorialPedido.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Pedido no encontrado'}, status=404)
# endregion

#region estados pedido
@require_POST
@transaction.atomic
def cambiar_estado_pedido(request, codigo_pedido):
    try:
        # Get user role and ID from session
        role = request.session.get('role')
        user_id = request.session.get('user_id')
        try:
            role_int = int(role)
        except (ValueError, TypeError):
            return JsonResponse({'success': False, 'error': 'Permisos inválidos'}, status=403)

        # Check permissions (only admin)
        if not user_id or role_int != 1:
            return JsonResponse({'success': False, 'error': 'No tienes permisos para realizar esta acción'}, status=403)

        # Parse JSON body
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({'success': False, 'error': 'Datos inválidos'}, status=400)

        nuevo_estado = (data.get('estado') or '').strip()
        if not nuevo_estado or nuevo_estado not in ['Aprobado', 'Cancelado', 'Enviado', 'Entregado']:
            return JsonResponse({'success': False, 'error': 'Estado no válido'}, status=400)

        # Update the state in the database
        try:
            pedido = HistorialPedido.objects.get(CodigoPedido=codigo_pedido)
            pedido.Estado = nuevo_estado
            pedido.save()
        except HistorialPedido.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Pedido no encontrado'}, status=404)

        return JsonResponse({
            'success': True,
            'nuevo_estado': nuevo_estado,
            'message': f'Estado actualizado correctamente a {nuevo_estado}',
            'redirect_url': reverse('solicitud')
        })

    except Exception as e:
        logger.exception("Error al cambiar estado del pedido %s: %s", codigo_pedido, str(e))
        return JsonResponse({'success': False, 'error': f'Error interno: {str(e)}'}, status=500)

def solicitud(request):
    pedidos_espera = HistorialPedido.objects.filter(Estado='Solicitado').order_by('-Fecha')

    pedidos_aprobados = HistorialPedido.objects.filter(Estado='Aprobado').order_by('-Fecha')

    pedidos_cancelados = HistorialPedido.objects.filter(Estado='Cancelado').order_by('-Fecha')

    pedidos_enviados = HistorialPedido.objects.filter(Estado='Enviado').order_by('-Fecha')
    pedidos_entregados = HistorialPedido.objects.filter(Estado='Entregado').order_by('-Fecha')

    def procesar_pedidos(pedidos_query):
        pedidos = []
        for pedido in pedidos_query:
            detalles = HistorialPedidoDetalle.objects.filter(HistorialId=pedido).select_related('ProductoId')
            
            pedidos.append({
                'codigo_pedido': pedido.CodigoPedido,
                'cliente': f"{pedido.UsuarioId.PrimerNombre} {pedido.UsuarioId.PrimerApellido}" if pedido.UsuarioId else "Invitado",
                'items': detalles,
                'total': pedido.Total,
                'fecha': pedido.Fecha,
                'estado': pedido.Estado,
            })
        return pedidos

    context = {
        'pedidos_espera': procesar_pedidos(pedidos_espera),
        'pedidos_aprobados': procesar_pedidos(pedidos_aprobados),
        'pedidos_cancelados': procesar_pedidos(pedidos_cancelados),
        'pedidos_enviados': procesar_pedidos(pedidos_enviados),
        'pedidos_entregados': procesar_pedidos(pedidos_entregados),
    }

    return render(request, 'solicitud.html', context)
#endregion

#region productos filtrados por subcategoria
def productos_por_subcategoria(request, id_subcategoria):
    categorias = categoria.objects.all().prefetch_related('subcategoria_set')
    subcat = get_object_or_404(subcategoria, IdSubCategoria=id_subcategoria)
    productos = producto.objects.filter(IdSubCategoria=subcat).order_by('-IdProducto')

    return render(request, "productos_subcategoria.html", {
        'categorias': categorias,
        "subcategoria": subcat,
        "productos": productos
    })
#endregion

def carrito(request):
    return render(request, 'carrito/carrito.html')
