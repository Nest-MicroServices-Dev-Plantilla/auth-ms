import { Controller } from '@nestjs/common';
import { AuthService } from './auth.service';
import { MessagePattern, Payload } from '@nestjs/microservices';
import { LoginUserDTO, RegisterUserDTO } from './dto';

@Controller()
export class AuthController {
  constructor(private readonly authService: AuthService) {}


  @MessagePattern('auth.register.user')
  registerUser(@Payload() registerUserDTO: RegisterUserDTO){
    return this.authService.registerUser(registerUserDTO);
  }

  @MessagePattern('auth.login.user')
  loginUser(@Payload() loginUserDTO: LoginUserDTO){
    return this.authService.loginUser(loginUserDTO);
  }

  @MessagePattern('auth.verify.user')
  verifyToken(@Payload() token: string){
    return this.authService.verifyToken(token);
  }

}
