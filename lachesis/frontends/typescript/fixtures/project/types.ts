export interface Session {
  token: string;
  tenant: string;
}

export interface Principal {
  tenant: string;
  subject: string;
}

export interface WebhookRequest {
  body: { id: string };
}
