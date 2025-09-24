document.addEventListener('DOMContentLoaded', () => {
  // Al cargar la página, sincroniza el carrito local con el backend si el usuario está logueado
  const userDataElement = document.getElementById('user-data');
  if (userDataElement && userDataElement.dataset.username) {
    cargarCarritoDesdeBackend();
  } else {
    mostrarCarrito();
  }

  // Event listener para el formulario de pago
  const formPago = document.getElementById('formPago');
  if (formPago) {
    formPago.addEventListener('submit', function (e) {
      e.preventDefault();
      registrarPago();
    });
  }

  // Event listener para el botón de PayPal
  const btnPayPal = document.getElementById('btnPayPal');
  if (btnPayPal) {
    btnPayPal.addEventListener('click', function () {
      if (!verificarSesion()) return; // detener si no está logueado
      cargarCarritoDesdeBackend(); // sincroniza antes de pagar
      procesarPagoPayPal();
    });
  }
});

function goBack() {
  if (document.referrer && document.referrer !== window.location.href) {
    window.history.back();
  } else {
    window.location.href = "/"; // Ajusta si quieres mandarlo siempre al home o catálogo
  }
}

async function registrarPago() {
  const carrito = JSON.parse(localStorage.getItem('carrito')) || [];

  if (carrito.length === 0) {
    Swal.fire('Carrito vacío', 'Agrega productos antes de pagar.', 'info');
    return;
  }

  const pedido = {
    nombre: document.getElementById("nombreCompleto").value,
    direccion: document.getElementById("direccion").value,
    correo: document.getElementById("correo").value,
    telefono: document.getElementById("telefono").value,
    fechaEntrega: document.getElementById("fechaEntrega").value,
    carrito: carrito,
    total: calcularTotal(),
  };

  if (!pedido.nombre || !pedido.direccion || !pedido.correo || !pedido.telefono || !pedido.fechaEntrega) {
    Swal.fire('Campos incompletos', 'Por favor rellena todos los campos antes de pagar.', 'warning');
    return;
  }

  try {
    const response = await fetch('/registrar-pago/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': getCookie('csrftoken'),
      },
      body: JSON.stringify(pedido),
    });

    const data = await response.json();

    if (data.success) {
      Swal.fire({
        title: '¡Compra exitosa!',
        text: 'Tu compra fue registrada con éxito. Te llevaremos al historial.',
        icon: 'success',
        confirmButtonText: 'Ver historial'
      }).then(() => {
        localStorage.removeItem('carrito');
        const cartCount = document.getElementById('cartCount');
        if (cartCount) cartCount.textContent = '0';
      
        window.location.href = data.redirect;
      });
    } else {
      Swal.fire('Error', data.mensaje || 'Hubo un problema al registrar el pago.', 'error');
    }
  } catch (error) {
    console.error("Error en registrarPago:", error);
    Swal.fire('Error', 'No se pudo completar el pago.', 'error');
  }
}




/**
 * Agregar producto al backend
 */
async function agregarProductoAlCarritoBackend(idProducto, cantidad = 1) {
  try {
    await fetch('/api/agregar-producto-carrito/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': getCookie('csrftoken'),
      },
      body: JSON.stringify({ id_producto: idProducto, cantidad }),
    });
    cargarCarritoDesdeBackend();
  } catch (error) {
    Swal.fire('Error', 'No se pudo agregar el producto al carrito.', 'error');
  }
}

function agregarAlCarrito(idProducto, cantidad = 1) {
  if (!verificarSesion()) return;
  agregarProductoAlCarritoBackend(idProducto, cantidad);
}

/**
 * Verifica si el usuario ha iniciado sesión.
 */
function verificarSesion() {
  const userDataElement = document.getElementById("user-data");
  const username = userDataElement && userDataElement.dataset.username
    ? userDataElement.dataset.username.trim()
    : "";

  console.log("username detectado:", username);

  if (username !== "") {
    return true; // ✅ usuario logueado
  }

  Swal.fire({
    title: 'Debes iniciar sesión',
    text: 'Por favor, inicia sesión para continuar con la compra.',
    icon: 'warning',
    confirmButtonColor: '#f5365c',
    confirmButtonText: 'Iniciar Sesión'
  }).then((result) => {
    if (result.isConfirmed) {
      window.location.href = '/login/';
    }
  });
  return false;
}

/**
 * Procesar pago con PayPal
 */
function procesarPagoPayPal() {
  const carrito = JSON.parse(localStorage.getItem('carrito')) || [];
  if (carrito.length === 0) {
    Swal.fire('Carrito vacío', 'Agrega productos antes de pagar.', 'info');
    return;
  }

  const pedido = {
    nombre: document.getElementById("nombreCompleto").value,
    direccion: document.getElementById("direccion").value,
    correo: document.getElementById("correo").value,
    telefono: document.getElementById("telefono").value,
    fechaEntrega: document.getElementById("fechaEntrega").value,
    carrito: carrito,
    total: calcularTotal(),
  };

  // Validar campos básicos
  if (!pedido.nombre || !pedido.direccion || !pedido.correo || !pedido.telefono || !pedido.fechaEntrega) {
    Swal.fire('Campos incompletos', 'Por favor rellena todos los campos antes de pagar.', 'warning');
    return;
  }

  fetch("/pago-paypal-carrito/", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(pedido),
  })
    .then(response => response.json())
    .then(data => {
      if (data.error) {
        Swal.fire('Error', data.error, 'error');
        return;
      }

      // Inyectar el form de PayPal debajo del total
      document.getElementById("paypal-form-container").innerHTML = data.form_html;

      // Cerrar modal automáticamente
      const paymentModal = bootstrap.Modal.getInstance(document.getElementById('paymentModal'));
      if (paymentModal) {
        paymentModal.hide();
      }

      // 🔑 Resetear formulario para siguiente uso
      const formPago = document.getElementById("formPago");
      if (formPago) {
        formPago.reset();
      }
    })
    .catch(error => console.error("Error en procesarPagoPayPal:", error));
}

// Nueva función: Validar stock antes de PayPal
async function validarStockCarrito(carrito) {
  try {
    const response = await fetch('/api/validar-stock-carrito/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': getCookie('csrftoken'),
      },
      body: JSON.stringify({ carrito }),
    });
    const data = await response.json();
    if (!data.success) {
      Swal.fire('Error de Stock', data.mensaje || 'Stock insuficiente en algún producto', 'error');
      return false;
    }
    return true;
  } catch (error) {
    console.error('Error validando stock:', error);
    return false;
  }
}

function mostrarCarrito() {
  const cartContainer = document.getElementById('cart-container');
  const totalAmount = document.getElementById('total-amount');
  const carrito = JSON.parse(localStorage.getItem('carrito')) || [];

  if (!cartContainer || !totalAmount) {
    console.warn("Elementos 'cart-container' o 'total-amount' no encontrados.");
    return;
  }

  cartContainer.innerHTML = '';
  let total = 0;

  if (carrito.length === 0) {
    cartContainer.innerHTML = '<p class="text-center">Tu carrito está vacío.</p>';
    totalAmount.textContent = '$0.00';
    return;
  }

  carrito.sort((a, b) => b.IdProducto - a.IdProducto);
  carrito.forEach((producto) => {
    const plusDisabled = producto.cantidad >= producto.stock ? 'disabled' : '';
    const minusDisabled = producto.cantidad <= 1 ? 'disabled' : '';

    const item = document.createElement('div');
    item.className = 'card mb-3';
    item.innerHTML = `
      <div class="card-body d-flex justify-content-between align-items-center">
        <div class="d-flex align-items-center gap-3" style="max-width: 60%;">
          <img src="${producto.imagen}" alt="${producto.nombre}" style="width: 100px; height: 120px; object-fit: cover; border-radius: 10px;">
          <div>
            <h5 class="card-title mb-1">${producto.nombre}</h5>
            <p class="card-text mb-1">${producto.descripcion || ''}</p>
            <p class="card-text mb-1">Precio unitario: $${producto.precio.toLocaleString('es-CL')}</p>
          </div>
        </div>
        <div class="text-end" style="min-width: 160px;">
          <p class="mb-2 fw-bold">$${(producto.precio * producto.cantidad).toLocaleString('es-CL')}</p>
          <div class="d-flex flex-column align-items-end gap-2">
            <div class="d-flex align-items-center gap-2 mb-2">
              <button class="btn btn-sm btn-outline-secondary" onclick="cambiarCantidad('${producto.IdProducto}', -1)" ${minusDisabled}>-</button>
              <span>${producto.cantidad}</span>
              <button class="btn btn-sm btn-outline-secondary" onclick="cambiarCantidad('${producto.IdProducto}', 1)" ${plusDisabled}>+</button>
            </div>
            <button class="btn btn-sm btn-danger" onclick="eliminarDelCarrito('${producto.IdProducto}')">
              <i class="fas fa-trash-alt"></i>
            </button>
          </div>
        </div>
      </div>
    `;
    cartContainer.appendChild(item);
    total += producto.precio * producto.cantidad;
  });

  totalAmount.textContent = `$${total.toLocaleString('es-CL')}`;
} 

function eliminarDelCarrito(idProducto) {
  let carrito = JSON.parse(localStorage.getItem('carrito')) || [];
  carrito = carrito.filter(p => p.IdProducto != idProducto);
  localStorage.setItem('carrito', JSON.stringify(carrito));
  mostrarCarrito();
  sincronizarCarritoConBackend();
}

function cambiarCantidad(idProducto, cambio) {
  let carrito = JSON.parse(localStorage.getItem('carrito')) || [];
  const prod = carrito.find(p => p.IdProducto == idProducto);
  if (prod) {
    const maxStock = prod.stock !== undefined ? prod.stock : 99;
    let nuevaCantidad = prod.cantidad + cambio;
    if (nuevaCantidad < 1) nuevaCantidad = 1;
    if (nuevaCantidad > maxStock) nuevaCantidad = maxStock;
    prod.cantidad = nuevaCantidad;
    localStorage.setItem('carrito', JSON.stringify(carrito));
    mostrarCarrito();
    sincronizarCarritoConBackend();
  }
}

function clearCart() {
  Swal.fire({
    title: '¿Estás seguro?',
    text: 'Esto vaciará todo tu carrito.',
    icon: 'warning',
    showCancelButton: true,
    confirmButtonColor: '#f5365c',
    cancelButtonColor: '#6c757d',
    confirmButtonText: 'Sí, vaciar',
    cancelButtonText: 'No, cancelar'
  }).then((result) => {
    if (result.isConfirmed) {
      localStorage.removeItem('carrito');
      mostrarCarrito();
      Swal.fire('Carrito vaciado', '', 'success');
    }
  });
}

async function cargarCarritoDesdeBackend() {
  try {
    const response = await fetch('/api/obtener-carrito-usuario/');
    if (response.ok) {
      const data = await response.json();
      const carritoBackend = data.carrito || [];
      const carritoLocal = JSON.parse(localStorage.getItem('carrito')) || [];

      // Fusionar: sumar cantidades si existe el mismo producto
      const carritoFinal = [...carritoLocal];
      carritoBackend.forEach(prodBackend => {
        const prodLocal = carritoFinal.find(p => p.IdProducto === prodBackend.IdProducto);
        if (prodLocal) {
          prodLocal.cantidad = Math.max(prodLocal.cantidad, prodBackend.cantidad);
        } else {
          carritoFinal.push(prodBackend);
        }
      });

      localStorage.setItem('carrito', JSON.stringify(carritoFinal));
      mostrarCarrito();
    } else {
      mostrarCarrito();
    }
  } catch (error) {
    console.error("Error cargando carrito backend:", error);
    mostrarCarrito();
  }
}

async function sincronizarCarritoConBackend() {
  const userDataElement = document.getElementById('user-data');
  const isLoggedIn = userDataElement && userDataElement.dataset.username;
  if (!isLoggedIn) return;

  try {
    const carrito = JSON.parse(localStorage.getItem('carrito')) || [];
    const response = await fetch('/api/sincronizar-carrito/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': getCookie('csrftoken'),
      },
      body: JSON.stringify({ carrito }),
    });
    if (response.ok) {
      await cargarCarritoDesdeBackend();
    }
  } catch (error) {
    console.error('Error sincronizando carrito:', error);
  }
}

function onLoginSuccess() {
  sincronizarCarritoConBackend();
}

function onLogout() {
  mostrarCarrito();
}

/**
 * Calcula el total del carrito (suma de precio * cantidad)
 */
function calcularTotal() {
  const carrito = JSON.parse(localStorage.getItem('carrito')) || [];
  return carrito.reduce((acc, item) => acc + item.precio * item.cantidad, 0);
}

function getCookie(name) {
  let cookieValue = null;
  if (document.cookie && document.cookie !== '') {
    const cookies = document.cookie.split(';');
    for (let c of cookies) {
      const cookie = c.trim();
      if (cookie.startsWith(name + '=')) {
        cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
        break;
      }
    }
  }
  return cookieValue;
}


