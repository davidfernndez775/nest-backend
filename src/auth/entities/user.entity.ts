import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';

// creamos el formato de los documentos que se guardan en la base de datos
@Schema()
export class User {
  // Mongo pone por defecto el campo id
  // _id: string;
  @Prop({ unique: true, required: true })
  email: string;

  @Prop({ required: true })
  name: string;

  @Prop({ minlength: 6, required: true })
  // se pone el ? para no tener que enviar el password encriptado de vuelta al usuario
  password?: string;

  @Prop({ default: true })
  isActive: boolean;

  @Prop({ type: [String], default: ['user'] })
  roles: string[];
}

// exportamos el esquema creado
export const UserSchema = SchemaFactory.createForClass(User);
