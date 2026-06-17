# Servidor Flask para Mercado Pago

Muestra en una página LAN los pagos que Mercado Pago notifica por webhook.

## Configuración

1. Copiá `.env.example` a `.env`.
2. En `.env`, completá `MERCADOPAGO_ACCESS_TOKEN` con tu access token.
3. Opcional: completá `MERCADOPAGO_WEBHOOK_SECRET` con la clave secreta del webhook.

## Ejecutar

```powershell
python -m pip install -r requirements.txt
python app.py
```

La página local queda en:

```text
http://127.0.0.1:8081/
```

Para verla desde otro dispositivo en la misma red, usá la IP LAN de esta PC:

```text
http://TU_IP_LAN:8081/
```

## Webhook

El endpoint para Mercado Pago es:

```text
POST /webhook/mercadopago
```

Mercado Pago debe poder llegar a ese endpoint desde internet. Para pruebas locales necesitás publicar temporalmente el puerto con una URL pública, por ejemplo con ngrok o Cloudflare Tunnel, y configurar en Mercado Pago:

```text
https://TU_URL_PUBLICA/webhook/mercadopago
```

Activá el evento `payment`.

## Datos mostrados

La pantalla muestra monto, moneda, estado, nombre informado por Mercado Pago, email e identificación del pagador cuando la API los devuelve. Mercado Pago puede no exponer DNI/CUIL para todos los tipos de movimiento.
