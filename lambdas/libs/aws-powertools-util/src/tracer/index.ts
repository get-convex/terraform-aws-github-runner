import { Tracer, captureLambdaHandler } from '@aws-lambda-powertools/tracer';

const tracer = new Tracer({
  serviceName: process.env.SERVICE_NAME || 'runners',
});

function getTracedAWSV3Client<T>(client: T): T {
  return tracer.captureAWSv3Client(client);
}
export { tracer, captureLambdaHandler, getTracedAWSV3Client };
