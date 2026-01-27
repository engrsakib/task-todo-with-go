import { Button } from "@/components/ui/button";
import { Card, CardTitle } from "@/components/ui/card";
import { toast } from "sonner";

const Login = () => {
  
  // === handle google login ===
  const handleGoogleLogin = () => {
    toast.success("[MOCK]: Google Login Done!");
  };

  return (
    <div className="h-screen w-full flex flex-col items-center justify-center p-4 bg-muted">
      <Card className="px-6 w-full max-w-xs mx-auto">
        <CardTitle className="text-xl font-semibold">Welcome Back!</CardTitle>
        <Button className="w-full" size="lg" onClick={handleGoogleLogin}>
          Login with Google
        </Button>
      </Card>
    </div>
  );
};

export default Login;
