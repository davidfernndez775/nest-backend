import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bycrypt from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';

import { CreateUserDto, LoginDto, RegisterUserDto, UpdateAuthDto } from './dto';
import { User } from './entities/user.entity';
import { JwtPayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
    private jwtService: JwtService,
  ) {}

  async create(createUserDto: CreateUserDto): Promise<User> {
    try {
      // desestructuramos el password y el resto de los datos
      const { password, ...userData } = createUserDto;
      const newUser = new this.userModel({
        password: bycrypt.hashSync(password, 10),
        ...userData,
      });
      // se usa el await para garantizar que si existe un error se ejecute
      // dentro del servicio
      await newUser.save();
      // en la respuesta de la peticion no se envia el password
      const { password: _, ...user } = newUser.toJSON();
      return user;
    } catch (error) {
      if (error.code === 11000) {
        throw new BadRequestException(`${createUserDto.email} already exists!`);
      }
      throw new InternalServerErrorException('Something wrong happened');
    }
  }

  async register(registerUserDto: RegisterUserDto): Promise<LoginResponse> {
    // obtengo los valores para el posterior login
    const { password, email, ...user } = registerUserDto;
    // creo el usuario
    await this.create(registerUserDto);
    // hago el login
    return this.login({ email: email, password: password });
  }

  async login(loginDto: LoginDto): Promise<LoginResponse> {
    const { email, password } = loginDto;
    const user = await this.userModel.findOne({ email: email });
    // chequeamos el usuario
    if (!user) {
      throw new UnauthorizedException('Not valid credentials');
    }
    // chequeamos el password
    if (!bycrypt.compareSync(password, user.password)) {
      throw new UnauthorizedException('Not valid password');
    }
    const { password: _, ...rest } = user.toJSON();
    return {
      user: rest,
      token: this.getJwtToken({ id: user.id }),
    };
  }

  findAll(): Promise<User[]> {
    return this.userModel.find();
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJwtToken(payload: JwtPayload) {
    const token = this.jwtService.sign(payload);
    return token;
  }
}
