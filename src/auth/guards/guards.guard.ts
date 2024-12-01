import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Observable } from 'rxjs';
import * as request from 'supertest';
import { JwtPayload } from '../interfaces/jwt-payload';
import { AuthService } from '../auth.service';

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    private jwtService: JwtService,
    private authService: AuthService,
  ) {}

  // la ruta o no en dependencia de una Promesa
  async canActivate(context: ExecutionContext): Promise<boolean> {
    // obtenemos la request
    const request = context.switchToHttp().getRequest();
    // extraemos el token
    const token = this.extractTokenFromHeader(request);
    // validamos que exista el token
    if (!token) {
      throw new UnauthorizedException('There is not bearer token');
    }
    try {
      const payload = await this.jwtService.verifyAsync<JwtPayload>(token, {
        secret: process.env.JWT_SEED,
      });
      const user = await this.authService.findUserById(payload.id);
      if (!user) throw new UnauthorizedException('User does not exists');
      if (!user.isActive) throw new UnauthorizedException('User is not active');
      request['user'] = user;
    } catch (error) {
      throw new UnauthorizedException();
    }

    return true;
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers['authorization']?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}
